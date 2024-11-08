import { getArgsAndRet, packArgs, parseType } from "../oc.js"
import { HK_TYPE } from "../../../../utils.js"

// typedef struct objc_selector *SEL;
type objc_selector = NativePointer // const char*
type SEL = objc_selector

// typedef id (*IMP)(id, SEL, ...);
type id = NativePointer
type IMP = (id: id, sel: SEL, ...args: NativePointer[]) => id
type IMPS = (...args: NativePointer[]) => id

export class OC_Hook_Status_IMPL {

    // global map save srcImpl to modifyImpl ptr
    static mapSrcToNewImpl: Map<NativePointer | ObjC.ObjectMethod, { newPtr: NativePointer, oldPtr: NativePointer }> = new Map()

    static getNewImplFromOld(oldPtr_: NativePointer): NativePointer {
        for (const [_key, value] of OC_Hook_Status.mapSrcToNewImpl) {
            if (value.oldPtr.equals(oldPtr_)) return value.newPtr
        }
        return NULL
    }

    static getNewImplFromOCMethod(objcMethod: NativePointer | ObjC.ObjectMethod) {
        return OC_Hook_Status.mapSrcToNewImpl.get(objcMethod)?.oldPtr
    }

    static addNew(objcMethod: NativePointer | ObjC.ObjectMethod, newPtr: NativePointer, oldPtr: NativePointer) {
        OC_Hook_Status.mapSrcToNewImpl.set(objcMethod, { newPtr: newPtr, oldPtr: oldPtr })
    }

    static has(objcMethod: NativePointer | ObjC.ObjectMethod) {
        for (const [key, _value] of OC_Hook_Status.mapSrcToNewImpl) {
            if ((key as ObjC.ObjectMethod).handle == objcMethod) return true
        }
        return false
    }

    static disp() {
        let index: number = 0
        newLine()
        for (const [key, value] of OC_Hook_Status.mapSrcToNewImpl) {
            let objM: ObjC.ObjectMethod = key as ObjC.ObjectMethod
            logd(`[${index++}] \tobjcMethod:${objM.handle} => { newPtr:${value.newPtr}, oldPtr:${value.oldPtr} }`)
        }
        newLine()
    }
}

class objc_method_local {

    private methodFHandle: ObjC.ObjectMethod | undefined

    private PTR_SEL: NativePointer = NULL
    private PTR_TYPES: NativePointer = NULL
    private PTR_IMPL: NativePointer = NULL

    public constructor(mPtr: NativePointer | number | string, methodName?: string) {
        let localP: NativePointer = NULL
        if (mPtr != undefined && methodName == undefined) {
            if (mPtr instanceof NativePointer || typeof mPtr === 'number' || (typeof mPtr === 'string' && mPtr.trim().startsWith('0x'))) {
                localP = mPtr instanceof NativePointer ? mPtr : ptr(mPtr)
                try {
                    const impl = localP.add(Process.pointerSize * 2).readPointer()
                    this.methodFHandle = addressToMethod(impl)
                } catch (error) { }
            } else throw new Error('Invalid argument')
        } else if (methodName != undefined && typeof mPtr === 'string') {
            this.methodFHandle = ObjC.classes[mPtr][methodName]
            localP = this.methodFHandle!.handle
        } else {
            throw new Error('Invalid argument')
        }
        this.PTR_SEL = localP
        this.PTR_TYPES = localP.add(Process.pointerSize)
        this.PTR_IMPL = localP.add(Process.pointerSize * 2)
    }

    public get address(): NativePointer { return this.PTR_IMPL.readPointer() }

    public get rva(): NativePointer {
        const md = Process.findModuleByAddress(this.address)
        return this.address.sub(md?.base!)
    }

    public get sel_ptr(): SEL { return this.PTR_SEL.readPointer() }

    public get sel(): string { return ObjC.selectorAsString(this.sel_ptr) }

    public get types(): string | null {
        return this.methodFHandle ?
            this.methodFHandle.types :
            this.PTR_TYPES.readPointer().readCString()
    }

    public get argsCount(): number {
        return this.methodFHandle ?
            this.methodFHandle.argumentTypes.length :
            call("method_getNumberOfArguments", this.PTR_SEL).toInt32()
    }

    // public invoke(...args: any[]) {
    //     if (!this.methodFHandle) throw new Error('Missing impl method call')
    //     if (args.length != this.argsCount - 2) throw new Error(`Invalid argument count [ expected ${this.argsCount - 2} but got ${args.length} ]`)
    //     return this.methodFHandle(...args)
    //     // return this.methodFHandle(Memory.allocUtf8String("test"))
    //     // return call(ObjC.api.objc_msgSend, this.methodFHandle.handle, this.sel_ptr, ...args.map(x => ptr(x as any)))
    // }

    public toString(): string { return `${this.PTR_SEL} -> ${this.address} -> ${this.rva} | ${this.sel} (${this.types})` }

    private get HookType() {
        return HK_TYPE.OBJC_REP
    }

    static count: number = 0
    public hook(hooktype: HK_TYPE = this.HookType, passPrivate: boolean = true, defaultArgsC: number = 6, force: boolean = false) {
        // if ((hooktype == HK_TYPE.FRIDA_ATTACH || hooktype == HK_TYPE.FRIDA_REP) && !force) {
        if (!force) {
            if (passPrivate && this.sel.startsWith('_')) {
                logw(`hooking ${this.address} -> ${this.sel} | pass private method`)
                return
            }
            if (this.sel.includes("alloc") || this.sel.includes("description")) {
                logw(`hooking ${this.address} -> ${this.sel} | pass filter method`)
                return
            }
        }
        switch (hooktype) {
            case HK_TYPE.FRIDA_ATTACH:
                const argsCount = this.argsCount
                try {
                    A(this.address, (args) => {
                        const argsStr = Array.from({ length: argsCount }, (_, i) => args[i].toString()).join(', ')
                        logd(`[ ${++objc_method_local.count} ]\tcalled ${argsStr}`)
                    })
                    logd(`hooking ${this.address} -> ${this.sel}`)
                } catch (error) {
                    loge(`hooking ${this.address} -> ${this.sel} | Error: ${error}`)
                }
                break
            case HK_TYPE.FRIDA_REP:
                let argsT: []
                if (this.methodFHandle) {
                    argsT = eval(`[ ${this.methodFHandle?.argumentTypes.map(i => `"${i}"`)} ]`)
                } else {
                    argsT = eval(`[ ${Array.from({ length: defaultArgsC }, (_, _i) => `"pointer"`).join(', ')} ]`)
                }
                try {
                    const srcCall = new NativeFunction(this.address, 'pointer', argsT) as IMPS
                    Interceptor.revert(this.address)
                    logz(`${this.sel} ${argsT}`)
                    Interceptor.replace(this.address, new NativeCallback(function (...args) {
                        let ret = srcCall(...arguments)
                        const argsStr = args.map((i, c) => {
                            const il: NativePointer = i as NativePointer
                            if (c == 0) return `${new ObjC.Object(il)} @ ${il}`
                            if (c == 1) return ObjC.selectorAsString(il)
                            return ptr(i as any)
                        }).join(', ')
                        logd(`[ ${++objc_method_local.count} ]\tcalled ${argsStr}`)
                        return ret
                    }, 'pointer', argsT))
                    logd(`hooking ${this.address} -> ${this.sel}`)
                } catch (error) {
                    loge(`hooking ${this.address} -> ${this.sel} | Error: ${error}`)
                }
                break
            case HK_TYPE.OBJC_REP:
                const method: ObjC.ObjectMethod | undefined = this.methodFHandle
                if (method == undefined) {
                    // return loge(`${this.address} -> ${this.sel} | Error: ObjMethod is NULL`)
                    return loge(`${this.address} -> ${this.sel} | Error: already replaced`)
                }
                const old_impl = method.implementation as any
                try {
                    const new_impl = ObjC.implement(method, function (clazz: NativePointer, selector: NativePointer, ...args: any[]) {
                        const ret = old_impl(clazz, selector, ...args)
                        const argsStr = args.map((i, _c) => i as NativePointer).join(', ')
                        const pk = getArgsAndRet(method.handle)
                        logd(`[ ${++objc_method_local.count} ]\tcalled ${new ObjC.Object(clazz)} @ ${clazz}, ${ObjC.selectorAsString(selector)} ${argsStr}`)
                        const retType = parseType(pk.ret)
                        if (retType != "void") {
                            let extInfo: string = retType
                            if (retType == "object") {
                                const retObj = new ObjC.Object(ret)
                                extInfo = `${retObj.$kind} of ${retObj.$className} @ ${retObj.$class.handle}`
                            }
                            logz(`retval  ${extInfo}\t${packArgs(ret, retType)}`)
                        }
                        for (let i = 0; i < pk.args.length - 2; i++) {
                            try {
                                const typeName = parseType(pk.args[i + 2])
                                let extInfo: string = typeName
                                if (typeName == "object") {
                                    const obj = new ObjC.Object(args[i])
                                    extInfo = `{ ${obj.$kind} of ${obj.$className} @ ${obj.$class.handle} }`
                                }
                                logz(`args[${i}] ${extInfo}\t${packArgs(args[i], typeName)}`)
                            } catch (error) {
                                loge(error)
                            }
                        }
                        return ret
                    })
                    method.implementation = new_impl
                    OC_Hook_Status.addNew(method, new_impl, old_impl)
                    logg(`hooking objM:${method.handle} ptr:${old_impl} new:${new_impl} -> ${this.sel}`)
                } catch (error) {
                    loge(`hooking objM:${method.handle} ptr:${old_impl} -> ${this.sel} \nError: ${error}`)
                }
                break
            default:
                throw new Error(`ERROR HookType`)
        }
    }

    detachOC() {

    }
}

declare global {
    var objc_method: typeof objc_method_local
    var OC_Hook_Status: typeof OC_Hook_Status_IMPL
}

globalThis.objc_method = objc_method_local
globalThis.OC_Hook_Status = OC_Hook_Status_IMPL