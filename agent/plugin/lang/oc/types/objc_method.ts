import { getArgsAndRet, packArgs, parseType } from "../oc.js"
import { HK_TYPE, printObjcStackTrace, TIME_SIMPLE } from "../../../../utils.js"

// typedef struct objc_selector *SEL;
type objc_selector = NativePointer // const char*
type SEL = objc_selector

// typedef id (*IMP)(id, SEL, ...);
type id = NativePointer
type IMP = (id: id, sel: SEL, ...args: NativePointer[]) => id
type IMPS = (...args: NativePointer[]) => id

type INFOS = { hook: HK_TYPE, modify: InvocationListener | NativeCallback<any, any>, ocMethodFullName: string, extra: any }

export class HookStatusManager_IMPL {

    static record: Map<string, INFOS> = new Map()

    /**
     * 
     * @param hookType hook type
     * @param srcImpl hook target
     * @param modifyImpl frida attach -> InvocationListener OR frida oc replacement -> NativeCallback<any, any>
     * @param ocMethodFullName 
     */
    static add(srcImpl: NativePointer, hookType: HK_TYPE, modifyImpl: InvocationListener | NativeCallback<any, any>, ocMethodFullName: string = '', extra: any = null): void {
        HookStatusManager_IMPL.record.set(srcImpl.toString(), { hook: hookType, modify: modifyImpl, ocMethodFullName: ocMethodFullName, extra: extra })
    }

    static remove(srcImpl: NativePointer): void {
        HookStatusManager_IMPL.record.delete(srcImpl.toString())
    }

    static update(srcImpl: NativePointer, hookType: HK_TYPE, modifyImpl: InvocationListener | NativeCallback<any, any>, ocMethodFullName: string = '', extra: any = null): void {
        HookStatusManager_IMPL.record.set(srcImpl.toString(), { hook: hookType, modify: modifyImpl, ocMethodFullName: ocMethodFullName, extra: extra })
    }

    static get(srcImpl: NativePointer, hooktype: HK_TYPE = HK_TYPE.FRIDA_ATTACH): INFOS | undefined {
        if (hooktype == HK_TYPE.FRIDA_ATTACH || hooktype == HK_TYPE.FRIDA_REP) return HookStatusManager_IMPL.record.get(srcImpl.toString())
        else if (hooktype == HK_TYPE.OBJC_REP) {
            // todo
            return undefined
        } else return undefined
    }

    // // global map save srcImpl to modifyImpl ptr
    // static mapSrcToNewImpl: Map<objc_method_pack, { newPtr: NativePointer, oldPtr: NativePointer }> = new Map()

    // static update(thisMethod: objc_method_pack, newPtr_arg: NativePointer = NULL, oldPtr_arg: NativePointer = NULL) {
    //     this.mapSrcToNewImpl.set(thisMethod, {
    //         newPtr: newPtr_arg,
    //         oldPtr: oldPtr_arg
    //     })
    // }

    // static getNewImplFromOld(oldPtr_: NativePointer): NativePointer {
    //     for (const [_key, value] of Hook_Status.mapSrcToNewImpl) {
    //         if (value.oldPtr.equals(oldPtr_)) return value.newPtr
    //     }
    //     return NULL
    // }

    // static getNewImplFromOCMethod(objcMethod: objc_method_pack) {
    //     return Hook_Status.mapSrcToNewImpl.get(objcMethod)?.oldPtr
    // }

    // static addNew(objcMethod: objc_method_pack, newPtr: NativePointer, oldPtr: NativePointer) {
    //     Hook_Status.mapSrcToNewImpl.set(objcMethod, { newPtr: newPtr, oldPtr: oldPtr })
    // }

    // static has(objcMethod: objc_method_pack): objc_method_pack | null {
    //     for (const [key, _value] of Hook_Status.mapSrcToNewImpl) {
    //         if (key.handle == objcMethod.handle) return key
    //     }
    //     return null
    // }
}

class objc_method_pack {

    private method!: ObjC.ObjectMethod
    private listener: InvocationListener | undefined

    private constructor() {

    }

    public static fromMethod(method: ObjectWrapper): objc_method_pack {
        const ins = new objc_method_pack()
        ins.method = method as ObjC.ObjectMethod
        return ins
    }

    public static fromAddress(mPtr: NativePointer): objc_method_pack {
        const ins = new objc_method_pack()
        ins.method = addressToMethod(mPtr)
        return ins
    }

    public static fromString(str: string): objc_method_pack {
        const ins = new objc_method_pack()
        ins.method = nameToMethod(str)
        return ins
    }

    public get handle(): NativePointer { return this.method.handle }

    public get name(): string | undefined { return ObjC.api.method_getName(this.method).readCString() as string }

    public get fullName(): string | undefined { return DebugSymbol.fromAddress(this.method.implementation).name! }

    public get address(): NativePointer | undefined { return this.method!.implementation }

    public get rva(): NativePointer {
        const md = Process.findModuleByAddress(this.address!)
        return this.address!.sub(md?.base!)
    }

    public get selector(): string { return this.method!.selector.readCString()! }

    // public invoke(...args: any[]) {
    //     if (!this.methodFHandle) throw new Error('Missing impl method call')
    //     if (args.length != this.argsCount - 2) throw new Error(`Invalid argument count [ expected ${this.argsCount - 2} but got ${args.length} ]`)
    //     return this.methodFHandle(...args)
    //     // return this.methodFHandle(Memory.allocUtf8String("test"))
    //     // return call(ObjC.api.objc_msgSend, this.methodFHandle.handle, this.sel_ptr, ...args.map(x => ptr(x as any)))
    // }

    // public toString(): string { return `${this.PTR_SEL} -> ${this.address} -> ${this.rva} | ${this.sel} (${this.types})` }

    static count_hook: number = 0
    static count_call: number = 0
    public hook(hooktype: HK_TYPE = HK_TYPE.FRIDA_ATTACH, passSomeMethods: boolean = true, bt: boolean = false) {
        if (!passSomeMethods) {
            if (this.selector.startsWith('_')) {
                logz(`[ ${++objc_method_pack.count_hook} ] pass -> ${this.address} ${this.selector} | private method`)
                return
            }
            if (this.selector.includes("alloc") || this.selector.startsWith(".")) {
                logz(`[ ${++objc_method_pack.count_hook} ] pass -> ${this.address} ${this.selector} | filter method name`)
                return
            }
        }

        // if (HookStatusManager_IMPL.get(this.method.implementation) !== undefined) {
        //     logz(`[ ${++objc_method_pack.count_hook} ] pass -> ${this.address} ${this.selector} | already hook`)
        //     return
        // }
        if (this.fullName == null) {
            logz(`[ ${++objc_method_pack.count_hook} ] pass -> ${this.address} ${this.selector} | already hook`)
            return
        }

        const pk = getArgsAndRet(this.method.handle)
        logw(`[ ${++objc_method_pack.count_hook} ] hook -> ${this.method.implementation} ${this.fullName} ${pk.args.length}`)
        let extraDes: string
        try {
            const md: Module | null = Process.findModuleByAddress(this.method.implementation)!
            let rva: string = `${this.method.implementation.sub(md.base!)}`
            extraDes = `R:${rva}`
        } catch (error) {
            // already modify
            extraDes = ''
        }
        const thisMethod = this
        switch (hooktype) {
            case HK_TYPE.FRIDA_ATTACH:
                // const cacheObj = HookStatusManager_IMPL.has(thisMethod)
                // if (cacheObj != null) cacheObj.detach()
                // HookStatusManager_IMPL.update(thisMethod)
                this.listener = Interceptor.attach(thisMethod.method.implementation, {
                    onEnter: function (args) {
                        const className = new ObjC.Object(args[0]).$className
                        this.titile = (`Called -> [ ${className} ] ${thisMethod.name} [ M:${thisMethod.method.handle} A:${thisMethod.method.implementation} ${extraDes} ]`)
                        let argsStr: string[] = []
                        pk.args.forEach((item, index) => {
                            argsStr.push(`args[${index}]\t->\t${item} - ${parseType(item)}\t${args[index]} ${packArgs(args[index], parseType(item))}`)
                        })
                        this.argumentsStr = argsStr.join('\n')
                    },
                    onLeave: function (retval) {
                        logo(`\n${getLine(85)}`)
                        logo(`${this.titile}`)
                        logd(`${this.argumentsStr}`)
                        if (parseType(pk.ret) == "void") {
                            logd(`retval\t->\t${pk.ret} - ${parseType(pk.ret)}`)
                        } else {
                            const retDetail = `${retval} ${packArgs(retval, parseType(pk.ret))}`
                            logd(`retval\t->\t${pk.ret} - ${parseType(pk.ret)}\t${retDetail}`)
                        }
                        if (bt) {
                            logo(`  [-] Call Stack (for ${thisMethod.name}):`)
                            const stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join('\n    |-- ')
                            logz(`    |-- ${stack}`)
                        }
                    }
                })
                break
            case HK_TYPE.FRIDA_REP:
                // todo ...

                // let argsT: []
                // if (this.methodFHandle) {
                //     argsT = eval(`[ ${this.methodFHandle?.argumentTypes.map(i => `"${i}"`)} ]`)
                // } else {
                //     argsT = eval(`[ ${Array.from({ length: defaultArgsC }, (_, _i) => `"pointer"`).join(', ')} ]`)
                // }
                // try {
                //     const srcCall = new NativeFunction(this.address, 'pointer', argsT) as IMPS
                //     Interceptor.revert(this.address)
                //     logz(`${this.sel} ${argsT}`)
                //     Interceptor.replace(this.address, new NativeCallback(function (...args) {
                //         let ret = srcCall(...arguments)
                //         const argsStr = args.map((i, c) => {
                //             const il: NativePointer = i as NativePointer
                //             if (c == 0) return `${new ObjC.Object(il)} @ ${il}`
                //             if (c == 1) return ObjC.selectorAsString(il)
                //             return ptr(i as any)
                //         }).join(', ')
                //         logd(`[ ${++objc_method_pack.count} ]\tcalled ${argsStr}`)
                //         return ret
                //     }, 'pointer', argsT))
                //     logd(`hooking ${this.address} -> ${this.sel}`)
                // } catch (error) {
                //     loge(`hooking ${this.address} -> ${this.sel} | Error: ${error}`)
                // }
                break
            case HK_TYPE.OBJC_REP:
                const old_impl = this.method.implementation as any
                try {
                    const new_impl: NativeCallback<any, any> = ObjC.implement(this.method, function (clazz: NativePointer, selector: NativePointer, ...args: any[]) {
                        const retval = old_impl(clazz, selector, ...args)
                        const className = new ObjC.Object(clazz).$className
                        logo(`\n${getLine(85)}`)
                        logo(`[${++objc_method_pack.count_call} | ${TIME_SIMPLE()} ] Called -> [ ${className} ] ${thisMethod.name} [ M:${thisMethod.handle} A:${thisMethod.method.implementation} ${extraDes} ]`)
                        const argsStr: string[] = []
                        pk.args.forEach((item, index) => {
                            const logType = parseType(item).padEnd(8, ' ')
                            if (index == 0) {
                                argsStr.push(`args[${index}]\t->\t${item}\t- ${logType}\t${clazz.toString().padEnd(13, ' ')} | ${packArgs(clazz, logType.trimEnd())}`)
                            }
                            else if (index == 1) {
                                argsStr.push(`args[${index}]\t->\t${item}\t- ${logType}\t${selector.toString().padEnd(13, ' ')} | ${packArgs(selector, logType.trimEnd())}`)
                            }
                            else {
                                let currentArg: NativePointer
                                try {
                                    // 这里有点奇怪，如果 ...args 长度是1，他就不是数组了
                                    currentArg = ptr(args[index - 2] as unknown as number)
                                } catch (error) {
                                    currentArg = ptr(args as unknown as number)
                                }
                                // for debug ↓
                                // loge(`args[${index}]\t->\t${item}\t- ${logType}\t${currentArg}\t${packArgs(currentArg, logType)}`)
                                // loge(packArg + " " + item)
                                let packArg = packArgs(currentArg, logType.trimEnd())
                                if (logType.trimEnd() == 'object' && !currentArg.isNull()) {
                                    const clsName = new ObjC.Object(currentArg).$className
                                    if (!packArg.includes(clsName)) packArg = `${clsName} ${packArg}`
                                }
                                argsStr.push(`args[${index}]\t->\t${item}\t- ${logType}\t${currentArg.toString().padEnd(13, ' ')} | ${packArg}`)
                            }
                        })
                        formatLog(argsStr)
                        const logType_ret = parseType(pk.ret).padEnd(8, ' ')
                        if (logType_ret.includes("void")) {
                            formatLog([`retval\t->\t${pk.ret}\t- ${logType_ret}`])
                        } else {
                            const retDetail = `${retval.toString().padEnd(13, ' ')} | ${retval} ${packArgs(retval, logType_ret.trimEnd())}`
                            formatLog([`retval\t->\t${pk.ret}\t- ${logType_ret}\t${retDetail}`])
                        }
                        if (bt)
                            printObjcStackTrace()
                        return retval
                    })
                    HookStatusManager_IMPL.add(this.method.implementation, HK_TYPE.OBJC_REP, new_impl, thisMethod.name) // record
                    this.method.implementation = new_impl
                } catch (error) {
                    loge(`${++objc_method_pack.count_hook} ] pass -> ${this.method.handle} -> ${this.method.selector} | Error: ${error}`)
                }
                break
            default:
                throw new Error(`ERROR HookType`)
        }

        function formatLog(msg: Array<string>) {
            msg.forEach(item => {
                const braceIndex = item.indexOf('{')
                if (braceIndex !== -1) {
                    const head = item.substring(0, braceIndex).trim()
                    const body = item.substring(braceIndex).trim()
                    logd(head)
                    body.split('\n').forEach(line => {
                        const trimmed = line.trim()
                        if (trimmed !== '') {
                            logz(`\t\t\t\t\t${trimmed}`)
                        }
                    })
                } else if (item.includes('\n')) {
                    const msg = item.split('|')
                    logd(`${msg[0]}`)
                    if (msg[1] != undefined && typeof (msg[1]) == "string" && msg[1] != '')
                        msg[1].trimStart().split('\n').forEach(item => logz(`\t\t\t\t\t${item}`))
                } else logd(item)
            })
        }
    }

    detach() {
        if (this.listener != undefined) this.listener.detach()
    }
}

declare global {
    var objc_method: typeof objc_method_pack
    var Hook_Status: typeof HookStatusManager_IMPL
}

globalThis.objc_method = objc_method_pack
globalThis.Hook_Status = HookStatusManager_IMPL