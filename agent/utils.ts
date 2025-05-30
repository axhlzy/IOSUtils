import { NSUTF8StringEncoding } from './constants.js'
import { SIGNAL } from './plugin/memory/findsvc.js'
import { NSString } from './types.js'
import './types.js'

// ... 单线程的js 这样只会显示最后的结果 ...
// 后续改改创建线程来轮询
export class ProcessDispTask {
    private _maxProgress: number = 100
    private _refreshTime: number = 200 // ms
    private _currentProgress: number = 0
    private _displayTitile: string = `Progress: `
    private _taskID: NodeJS.Timeout | undefined
    private _processRuning: boolean = false // runing ? 

    constructor(max: number = 100, refreshTime: number = 1000) {
        this._maxProgress = max
        this._refreshTime = refreshTime
        this._currentProgress = 0
        this.start()
    }

    public setMax(max: number) {
        this._maxProgress = max
    }

    private start() {
        this._processRuning = true
        this._taskID = setInterval(() => {
            if (this._currentProgress >= this._maxProgress) this.stop()
            if (!this._processRuning) return
            console.log('\x1Bc')
            console.warn(`${this._displayTitile} ${this._currentProgress * 100 / this._maxProgress}%\r`)
        }, this._refreshTime)
    }

    public stop() {
        clearInterval(this._taskID)
        this._processRuning = false
        console.log(`${this._displayTitile} ${this._currentProgress * 100 / this._maxProgress}%`)
    }

    public update(progress: number) {
        this._currentProgress = progress
    }
}

globalThis.ProcessDispTask = ProcessDispTask

globalThis.clear = () => console.log('\x1Bc')

globalThis.hex = (ptr: NativePointer | string | number, len: number = 0x40) => {
    let mPtr = NULL
    if (typeof ptr == 'string' && ptr.startsWith("0x")) mPtr = new NativePointer(ptr)
    else if (typeof ptr == 'number') mPtr = new NativePointer(ptr)
    else if (ptr instanceof NativePointer) mPtr = ptr
    if (mPtr.isNull()) throw new Error('ptr is null')
    console.log(hexdump(mPtr, { length: len, header: true, ansi: true }))
}

globalThis.dumpUI = () => {
    logd(ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString())
}

globalThis.checkPointer = (ptr: NativePointer | number | string | ObjC.Object | ObjC.ObjectMethod, throwErr: boolean = true): NativePointer => {
    let mPtr: NativePointer = NULL
    if (typeof ptr === 'string') {
        ptr = ptr.trim()
        if (ptr.startsWith('0x')) {
            mPtr = new NativePointer(parseInt(ptr, 16))
        } else {
            try {
                mPtr = ObjC.classes[ptr].handle
            } catch { }
            try {
                if (mPtr.isNull()) mPtr = DebugSymbol.fromName(ptr).address
            } catch { }
            if (mPtr.isNull()) {
                if (throwErr) throw new Error(`Invalid pointer <- cannot find '${ptr}'`)
                return NULL
            }
            return mPtr
        }
    } else if (typeof ptr === 'number') {
        mPtr = new NativePointer(ptr)
    } else if (ptr instanceof NativePointer) {
        mPtr = ptr
    } else if (ptr instanceof ObjC.Object) {
        mPtr = ptr.handle
    }
    if (throwErr && mPtr.isNull()) throw new Error('Invalid pointer')
    return mPtr
}

globalThis.allocOCString = (str: string): ObjC.Object => {
    if (str == undefined || str.length == 0 || str == null) throw new Error('Invalid string')
    return ObjC.classes["NSString"]["+ stringWithUTF8String:"](allocCString(str))
}

globalThis.allocCString = (str: string): NativePointer => {
    if (str == undefined || str.length == 0 || str == null) throw new Error('Invalid string')
    return Memory.allocUtf8String(str)
}

/**
 * 
 * @param ptr function address | asm start address
 * @param args arguments list | if call oc function, instance as first arg, use ObjC.selector or NSSelectorFromString as the secend arg
 * @returns function return value | NativePointer
 * @example
 * 
 * new ObjC.selector("xxx") === call("NSSelectorFromString", allocOCString("xxx"))
 * 
 * [ UILabel ] 0x102e07840
    UILabel ( 0x20310ec40 )  -> UIView ( 0x20310f668 )  -> UIResponder ( 0x203108f98 )  -> NSObject ( 0x2030ca1f0 )
    [ 0 ]    M: 0x1ba532e80 | - setTextColor:
    [ 1 ]    M: 0x1ba53393c | - setTextAlignment:
    [ 2 ]    M: 0x1ba5328d8 | - setText:
    [ 3 ]    M: 0x1ba533a40 | - setHighlightedTextColor:
    [ 4 ]    M: 0x1ba53ba58 | - setAutotrackTextToFit:
    
    call(0x1ba5328d8, 0x102e07840, ObjC.selector("- setText:"), allocOCString("123123123"))
 */
const debugLog: boolean = false
globalThis.call = (ptr: NativePointer | number | string | ObjC.Object, ...args: any[] | NativePointer[] | ObjC.Object[]): NativePointer => {
    try {
        const target = checkPointer(ptr)
        if (debugLog) logw(`Called -> Address: ${target}${typeof ptr == "string" ? ` ${ptr}\t` : ''} | Arguments [ ${args.length} ] -> ${args}`)
        const argsStr = args.map(arg => typeof arg === 'number' ? `"pointer"` : `"pointer"`).join(', ') // All types are treated as pointer
        const func = eval(`new NativeFunction(new NativePointer(${target}), 'pointer', [ ${argsStr} ])`)
        if (typeof func !== 'function') throw new Error("Error while Created NativeFunction")
        return func(...args.map(item => checkPointer(item as any)))
    } catch (error) {
        throw new Error(`Error during call: \n\t${error}`)
    }
}

globalThis.callOC = (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args): NativePointer => {
    return new ObjC.Object(checkPointer(objPtr))[funcName](...args)
    // return call(ptr(new ObjC.Object(checkPointer(objPtr))[funcName].implementation), objPtr, ObjC.selector(funcName), ...args)
}

/**
 * OC call on main thread
 * 
 * @param objPtr 
 * @param funcName 
 * @param args 
 * 
 * example : callOcOnMain(0x102e07840, "- setText:", allocOCString("test"))
 */
globalThis.callOcOnMain = (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any): void => {
    ObjC.schedule(ObjC.mainQueue, () => {
        const ret = callOC(objPtr, funcName, ...args)
        if (ret != undefined) logd(`${ret}`)
    })
}

const bytesToUTF8 = (data: any): string => {
    // Sample Objective-C
    // char buf[] = "\x41\x42\x43\x44";
    // NSString *p = [[NSString alloc] initWithBytes:buf length:5 encoding:NSUTF8StringEncoding];
    if (data === null) {
        return ""
    }
    if (!data.hasOwnProperty("bytes")) {
        return data.toString()
    }
    const s: NSString = ObjC.classes.NSString.alloc().initWithBytes_length_encoding_(
        data.bytes(), data.length(), NSUTF8StringEncoding)
    if (s) {
        return s.UTF8String()
    }
    return ""
}

globalThis.getIvars = (clazz: NativePointer | string | number | ObjC.Object): Array<{ objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }> => {
    const mPtr = checkPointer(clazz)
    const obj: ObjC.Object = new ObjC.Object(mPtr) // class handle
    if (obj.$kind != "instance") throw new Error("Wrong Object ptr\nclass_copyIvarList api only support instance ptr as first argument")

    const classHandles = []
    let currentClassHandle = obj.$class.handle
    do {
        classHandles.unshift(currentClassHandle)
        currentClassHandle = ObjC.api.class_getSuperclass(currentClassHandle)
    } while (!currentClassHandle.isNull())

    const retValue: Array<{ objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }> = new Array()
    const numIvarsBuf = Memory.alloc(Process.pointerSize)
    classHandles.forEach(clazz => {
        const ivarHandles = ObjC.api.class_copyIvarList(clazz, numIvarsBuf)
        try {
            const numIvars = numIvarsBuf.readUInt()
            for (let i = 0; i !== numIvars; i++) {
                const handle = ivarHandles.add(i * Process.pointerSize).readPointer()
                const name = ObjC.api.ivar_getName(handle).readUtf8String()
                const offset = ObjC.api.ivar_getOffset(handle).toInt32()
                retValue.push({ objClazz: new ObjC.Object(clazz), handle: handle, name: name, offset: offset })
            }
        } finally {
            ObjC.api.free(ivarHandles)
        }
    })
    return retValue
}

globalThis.showIvars = (clazz: NativePointer | string | number | ObjC.Object): void => {
    const mPtr = checkPointer(clazz)
    let obj: ObjC.Object = new ObjC.Object(mPtr) // obj handle
    showSuperClasses(obj.handle)
    const res: { objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }[] = getIvars(obj.handle)

    const groupedByObjClazz = res.reduce((acc, item) => {
        const clazzKey = item.objClazz.toString()
        if (!acc[clazzKey]) {
            acc[clazzKey] = []
        }
        acc[clazzKey].push(item)
        return acc
    }, {} as Record<string, { objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }[]>)

    Object.keys(groupedByObjClazz).forEach((clazzKey) => {
        logn(`\n--- ${ObjC.classes[clazzKey].handle} & ${clazzKey} ---`)
        groupedByObjClazz[clazzKey].forEach((item, index) => logd(`[ ${index} ]\t${ptr(item.offset)} -> ${item.name}`))
    })
    newLine()
}

globalThis.lfs = (ptrArg: NativePointer | string | number, ret: boolean = false) => {
    const mPtr = checkPointer(ptrArg)
    const obj = new ObjC.Object(mPtr) // class handle
    if (obj.$kind != "instance") throw new Error("ivars | can only parse instance")
    showSuperClasses(obj.$class)

    const res = getIvars(obj.handle)
    const groupedByObjClazz = res.reduce((acc, item) => {
        const clazzKey = item.objClazz.toString()
        if (!acc[clazzKey]) {
            acc[clazzKey] = []
        }
        acc[clazzKey].push(item)
        return acc
    }, {} as Record<string, { objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }[]>)

    const $clonedIvars: { [name: string]: any } = {}
    const vars = obj.$ivars

    Object.keys(groupedByObjClazz).forEach((clazzKey) => {
        logn(`\n--- ${ObjC.classes[clazzKey].handle} & ${clazzKey} ---`)
        groupedByObjClazz[clazzKey].forEach((item, index) => {
            try {
                const name = item.name
                if (vars.hasOwnProperty(name)) {
                    const v = vars[name] as Object
                    $clonedIvars[name] = bytesToUTF8(v)
                    if (ret) return
                    if (v instanceof ObjC.Object) {
                        const clsName = v.$className
                        let ext = ''
                        try {
                            switch (clsName) {
                                case '__NSCFString':
                                    // 特值处理，当然这里这样写是没必要的，只是单独摘出来而已
                                    ext = `-> "${new ObjC.Object(v.handle)}"`
                                    break
                                default:
                                    if (!v.handle.isNull()) {
                                        let objStr = asOcObjtoString(v.handle)
                                        if (objStr.includes("\n")) {
                                            const lines = objStr.split("\n")
                                            objStr = lines.map(line => `\t\t${line}`).join("\n")
                                            objStr = `\n${objStr}`
                                        }
                                        ext = `-> ${objStr}`
                                    }
                                    break
                            }
                        } catch (error) { }
                        logd(`[ ${index} ]\t${ptr(item.offset)} [ ${ptr(item.offset).add(mPtr)} ] -> ${name}: | ObjC.Object <- ${v.$kind} of ${clsName} @ ${v.$class.handle}`)
                        logz(`\t${v.handle} ${ext}`)
                    } else if (typeof v == "object") {
                        logd(`[ ${index} ]\t${ptr(item.offset)} [ ${ptr(item.offset).add(mPtr)} ] -> ${name}: | ${typeof v}`)
                        logz(`\t${v}`)
                    } else {
                        logd(`[ ${index} ]\t${ptr(item.offset)} [ ${ptr(item.offset).add(mPtr)} ] -> ${name}: | ${typeof v}`)
                        logz(`\t${$clonedIvars[name]}`)
                    }
                }
            } catch (error) {
                logd(`[ ${index} ]\t${ptr(item.offset)} [ ${ptr(item.offset).add(mPtr)} ] -> ${item.name}: | Error accessing value`)
            }
        })
    })
    newLine()

    if (ret) return $clonedIvars
}

// similar to x/a (lldb) 
/**
 * example:
 * can use at block
 * [Remote::MobileSMS ]-> xa(0x280c5bd18)
    0x280c5bd18 -> 0x280c5bd20         |
    0x280c5bd18 -> 0x1f6528a68         |    libsystem_blocks.dylib ! _NSConcreteMallocBlock
    0x280c5bd18 -> 0xc3000002          |
    0x280c5bd18 -> 0x1a1bee114         |    ContactsAutocompleteUI ! __44-[CNComposeRecipientTextView initWithFrame:]_block_invoke
    0x280c5bd18 -> 0x1ef275b48         |    ContactsAutocompleteUI ! __block_descriptor_40_e8_32w_e24_v16?0"NSNotification"8l
 */
globalThis.xa = (ptr: NativePointer | string | number, count: number = 5): void => {
    newLine()
    logd(xas(ptr))
    newLine()
}

globalThis.xas = (ptr: NativePointer | string | number, count: number = 5, split:string = '|'): string => {
    const mPtr = checkPointer(ptr)
    let ret = ''
    for (let i = 0; i < count; i++) {
        const indexAddress = mPtr
        const current = indexAddress.add(i * Process.pointerSize).readPointer()
        const sym = DebugSymbol.fromAddress(current)
        const mdName = sym.moduleName
        const symDisp = mdName == null ? '' : `${mdName} ! ${sym.name}`
        ret += `${indexAddress} -> ${current.toString().padEnd(4 + Process.pointerSize * 2, ' ')}${split}\t${symDisp}\n`
    }
    return ret.trimEnd()
}

globalThis.getBacktrace = (ctx: CpuContext): string => `called from:\n${Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`

globalThis.printBacktrace = (ctx: CpuContext): void => log(getBacktrace(ctx))

globalThis.raise = (sign: SIGNAL = SIGNAL.SIGSTOP): number => new NativeFunction(Module.findExportByName(null, 'raise')!, 'int', ['int'])(sign)

// globalThis.lfs = (ptr: NativePointer | string | number, ret: boolean = false) => {
//     const mPtr = checkPointer(ptr)
//     const obj = new ObjC.Object(mPtr) // class handle
//     if (obj.$kind != "instance") throw new Error("ivars | can only parse instance")
//     showSuperClasses(obj.handle)
//     const $clonedIvars: { [name: string]: any } = {}
//     const vars = obj.$ivars
//     let index: number = 0

//     // frida-oc-bridge impl
//     for (const k in vars) {
//         try {
//             if (vars.hasOwnProperty(k)) {
//                 const v = vars[k] as Object
//                 $clonedIvars[k] = bytesToUTF8(v)
//                 if (ret) continue
//                 if (v instanceof ObjC.Object) {
//                     logd(`[${++index}] ${k}: | ObjC.Object <- ${v.$kind} of ${v.$className} @ ${v.$class.handle}`)
//                     logz(`\t${v.handle}`)
//                 } else if (typeof v == "object") {
//                     logd(`[${++index}] ${k}: | ${typeof v}`)
//                     logz(`\t${v}`)
//                 } else {
//                     logd(`[${++index}] ${k}: | ${typeof v}`)
//                     logz(`\t${$clonedIvars[k]}`)
//                 }
//             }
//         } catch (error) {

//         }
//     }
//     if (ret) return $clonedIvars
// }

enum passValueKey {
    org = "org",
    src = "src",
    enter = "enter",
    leave = "leave",
    time = "time"
}
export type ARGM = NativePointer | number | any
export type PassType = passValueKey | string
var map_attach_listener = new Map<string, InvocationListener>()
export type OnEnterType = (args: InvocationArguments, ctx: CpuContext, passValue: Map<PassType, any>) => void
export type OnExitType = (retval: InvocationReturnValue, ctx: CpuContext, passValue: Map<PassType, any>) => void
const attachNative = (mPtr: ARGM, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord: boolean = true): void => {
    if (typeof mPtr == "number") mPtr = ptr(mPtr)
    if (mPtr instanceof NativePointer && mPtr.isNull()) return
    var passValue = new Map()
    passValue.set(passValueKey.org, mPtr)
    passValue.set(passValueKey.src, mPtr)
    passValue.set(passValueKey.enter, mOnEnter)
    passValue.set(passValueKey.leave, mOnLeave)
    passValue.set(passValueKey.time, new Date())
    mPtr = checkPointer(mPtr)
    let Listener = Interceptor.attach(mPtr, {
        onEnter: function (args: InvocationArguments) {
            if (mOnEnter != undefined) mOnEnter(args, this.context, passValue)
        },
        onLeave: function (retval: InvocationReturnValue) {
            if (mOnLeave != undefined) mOnLeave(retval, this.context, passValue)
        }
    })
    if (needRecord) map_attach_listener.set(String(mPtr), Listener)
}

const detachAll = (mPtr?: ARGM) => {
    if (typeof mPtr == "number") mPtr = ptr(mPtr)
    if (mPtr == undefined) {
        map_attach_listener.clear()
        Interceptor.detachAll()
    } else {
        let key = String(checkPointer(mPtr))
        let listener = map_attach_listener.get(key)
        if (listener != undefined) {
            listener.detach()
            map_attach_listener.delete(key)
        }
    }
}

var arr_nop_addr = new Array()
type ReplaceFunc = NativeFunction<NativePointer, [NativePointerValue, NativePointerValue, NativePointerValue, NativePointerValue]>
type ReplaceFuncType = (srcCall: ReplaceFunc, arg0: NativePointer, arg1: NativePointer, arg2: NativePointer, arg3: NativePointer) => any
function replaceFunction(mPtr: ARGM, callBack: ReplaceFuncType, TYPENOP: boolean = true): void {
    mPtr = checkPointer(mPtr)
    if (String(arr_nop_addr).indexOf(String(mPtr)) == -1) {
        arr_nop_addr.push(String(mPtr))
    } else {
        Interceptor.revert(mPtr)
    }
    const srcFunc = new NativeFunction(mPtr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
    Interceptor.replace(mPtr, new NativeCallback((arg0, arg1, arg2, arg3) => {
        logw("\nCalled " + (TYPENOP ? "Replaced" : "Nop") + " function ---> " + mPtr)
        const ret = callBack(srcFunc, arg0, arg1, arg2, arg3)
        return ret == null ? ptr(0) : ret
    }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']))
}

const nopFunction = (mPtr: ARGM): void => {
    if (typeof mPtr == "number") mPtr = ptr(mPtr)
    if (mPtr == undefined) return
    replaceFunction(mPtr, () => ptr(0), true)
}

const cancelNop = (mPtr: ARGM): void => {
    mPtr = checkPointer(mPtr)
    Interceptor.revert(mPtr)
    for (let i = 0; i < arr_nop_addr.length; i++) {
        if (String(arr_nop_addr[i]) == String(mPtr)) {
            arr_nop_addr = arr_nop_addr.splice(arr_nop_addr[i], 1)
        }
    }
}

const cancelAllNopedFunction = () => arr_nop_addr.forEach((addr) => Interceptor.revert(addr))

const stk = (mPtr: NativePointer) => {
    Interceptor.attach(checkPointer(mPtr), {
        onEnter: function (args) {
            logw(`ENTER: ${mPtr}\n\tINS=${new ObjC.Object(args[0])} SEL=${ObjC.selectorAsString(args[1])}`)
            logw(`\tARG2=${new ObjC.Object(args[2])} ARG3=${new ObjC.Object(args[3])} ... `)

            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    exec: true
                },
                onReceive: function (events) {
                    const bbs = Stalker.parse(events, {
                        stringify: false,
                        annotate: false
                    });
                    logd(bbs.flat().map(item => DebugSymbol.fromAddress(ptr(item as unknown as string))).join('\n'));
                }
            })
        },
        onLeave: function (retval) {
            Stalker.unfollow()
            Stalker.flush()
        }
    })
}

globalThis.isObjcInstance = (mPtr: NativePointer): NativePointer => {
    if (mPtr == undefined || mPtr.isNull()) return NULL
    try {
        return call("object_getClass", mPtr).readPointer()
    } catch (error) {
        return NULL
    }
}

// +[UPWDeviceUtil deviceOSVersion] => {clsName, methodName}
// globalThis.nameToMethod = (method: string): ObjC.ObjectMethod => {
//     if (method[1] == '[' && method.endsWith(']')) {
//         const methodL = method.slice(2, -1)
//         const parts = methodL.split(' ')
//         if (parts.length != 2) throw new Error("Invalid format, there should be exactly one space.")
//         const className = parts[0]
//         const classMethod = `${method[0]} ${parts[1]}`
//         return ObjC.classes[className][classMethod]
//     } else {
//         throw new Error("Invalid format, should start with '+[' / '-[' and end with ']'")
//     }
// }
globalThis.nameToMethod = (method: string): ObjC.ObjectMethod => {
    if (method[1] === '[' && method.endsWith(']')) {
        const methodContent = method.slice(2, -1).trim()  // 去掉前缀 -[ 和 后缀 ]
        const parts = methodContent.split(' ')
        if (parts.length < 2) {
            throw new Error("Invalid format, should contain class and selector.")
        }

        const className = parts[0]

        // 将后续部分合并回 selector 字符串（并剔除地址参数）
        const selectorRaw = parts.slice(1).join(' ')
        // 将带地址的选择器（比如 xxx:0x123 yyy:0x456）转为 xxx:yyy:
        const selectorCleaned = selectorRaw
            .split(/\s+/)
            .map(seg => {
                const colonIndex = seg.indexOf(':')
                return colonIndex !== -1 ? seg.substring(0, colonIndex + 1) : seg
            })
            .join('')

        const fullSelector = `${method[0]} ${selectorCleaned}` // 恢复成 `- selector:` 形式
        return ObjC.classes[className][fullSelector]
    } else {
        throw new Error("Invalid format, should start with '+[' / '-[' and end with ']'")
    }
}

export const TIME_SIMPLE = (): string => new Date().toLocaleTimeString().split(" ")[0]

globalThis.addressToMethod = (mPtr: NativePointer | number): ObjC.ObjectMethod => nameToMethod(DebugSymbol.fromAddress(mPtr instanceof NativePointer ? mPtr : ptr(mPtr)).name!)

globalThis.showAsm = (mPtr: NativePointer, len: number = 0x20) => {
    const l_mPtr = checkPointer(mPtr)
    let next: NativePointer = l_mPtr
    newLine()
    const sym = DebugSymbol.fromAddress(l_mPtr)

    let status_func_start: boolean = false
    let method: undefined | ObjC.ObjectMethod = undefined
    let methodCount: number = 2
    type Args = { index: number; address: NativePointer; extra: string }
    const argsMap = new Map<number, Args>();

    // log function title
    if (sym.moduleName != null && sym.name != null) {
        const base = new ApiResolver('objc').enumerateMatches(sym.name)[0].address
        let ext: string = ''
        if (!base.equals(sym.address)) ext += `${sym.address.sub(base)}`
        else {
            status_func_start = true
            method = addressToMethod(base)
            methodCount = call("method_getNumberOfArguments", method.handle).toInt32()
        }
        logw(`${sym.moduleName} | ${sym.name} @ ${base} ${ext}\n`)
    }

    // instruction iterator
    while (len-- > 0) {
        try {
            // only deal with arm64
            const ins = Instruction.parse(next) as Arm64Instruction
            const logMsg = `\t${ins.address} ${ins.mnemonic} ${ins.opStr}`
            check_instance_args(ins, methodCount) ? loge(logMsg) : logd(logMsg)
            check_info_BL_B(ins)
            check_info_LDR_ADD(ins)
            next = ins.next
        } catch (error) {
            // ...
        }
    }
    newLine()
    LOGJSON(argsMap)

    function check_info_BL_B(ins: Arm64Instruction): void {
        try {
            const op = ins.operands[0]
            // check bl 
            if ((ins.mnemonic == 'bl' || ins.mnemonic == 'b') && op.access == "r" && op.type == "imm")
                logz(`\t\t-> ${DebugSymbol.fromAddress(ptr(op.value.toNumber())).name}`)
        } catch (error) {
            // do notiong
            loge(error)
        }
    }

    function check_info_LDR_ADD(ins: Arm64Instruction): void {
        try {
            // check 
            // 0x10435b438 adrp x0, #0x104621000
            // 0x10435b43c add x0, x0, #0x8c8
            if (ins.mnemonic == 'add'
                && ins.operands[0].access == "w" && ins.operands[0].type == "reg"
                && ins.operands[1].access == "r" && ins.operands[1].type == "reg"
                && ins.operands[2].access == "r" && ins.operands[2].type == "imm"
                && ins.regsAccessed.read.toString() == ins.regsAccessed.written.toString()
            ) {
                const offet = ins.operands[2].value.toNumber()
                const lastIns = Instruction.parse(ins.address.sub(ins.size)) as Arm64Instruction
                if (lastIns.mnemonic == 'adrp'
                    && lastIns.operands[0].access == "w" && lastIns.operands[0].type == "reg"
                    && lastIns.operands[1].access == "r" && lastIns.operands[1].type == "imm"
                    && lastIns.regsAccessed.written.toString() == ins.regsAccessed.read.toString()) {
                    const base = lastIns.operands[1].value.toNumber()
                    const addr = ptr(base).add(offet)
                    try {
                        const name = DebugSymbol.fromAddress(addr).name
                        if (name != null) {
                            logz(`\t\t-> ${addr} ${name}`)
                        } else {
                            const p = addr.readPointer().readPointer()
                            logz(`\t\t! ${p} "${new ObjC.Object(addr)}" | ${DebugSymbol.fromAddress(p).name}`)
                        }
                    } catch (error) {
                        loge(error)
                    }
                }
            }
        } catch (error) {
            loge(error)
        }
    }

    function check_instance_args(ins: Arm64Instruction, findNumberOfargs: number = 2): boolean {
        if (!status_func_start || argsMap.size == findNumberOfargs) return false
        for (let regIndex = 0; regIndex < findNumberOfargs; regIndex++) {
            const condition_operands_r = ins.operands.find(op => op.access == "r" && op.type == "reg" && op.value.toString() == `x${regIndex}`)
            const condition_regsAccessed_r = ins.regsAccessed.read.toString().includes(`x${regIndex}`)
            if (condition_operands_r && condition_regsAccessed_r) {
                return addToArgsArray({
                    index: regIndex,
                    address: ins.address,
                    extra: ins.opStr
                })
            }
        }
        return false

        function addToArgsArray(args: Args) {
            if (!argsMap.has(args.index)) {
                argsMap.set(args.index, args)
                return true
            } else return false
        }
    }
}

globalThis.dis = globalThis.showAsm

globalThis.asOcObj = (mPtr: NativePointer | string) => {
    return new ObjC.Object(ptr(mPtr as unknown as string))
}

globalThis.asOcObjtoString = (mPtr: NativePointer | string) => {
    return decodeURIComponent(new ObjC.Object(ptr(mPtr as unknown as string)).toString()).toString()
}

globalThis.asOcString = (mPtr: NativePointer | string) => {
    logd(decodeURIComponent(new ObjC.Object(ptr(mPtr as unknown as string)).toString()))
}

globalThis.asOcSELtoString = (mPtr: NativePointer | string) => {
    return ObjC.selectorAsString(ptr(mPtr as unknown as string))
}

globalThis.demangleName = (expName: string): string => {
    // DebugSymbol.fromName("__cxa_demangle")
    const demangleAddress: NativePointer | null = Module.findExportByName(null, '__cxa_demangle')
    if (demangleAddress == null) throw Error("can not find export function -> __cxa_demangle")
    const demangle: Function = new NativeFunction(demangleAddress, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
    const mangledName: NativePointer = Memory.allocUtf8String(expName)
    const outputBuffer: NativePointer = NULL
    const length: NativePointer = NULL
    const status: NativePointer = Memory.alloc(Process.pageSize)
    const result: NativePointer = demangle(mangledName, outputBuffer, length, status) as NativePointer
    if (status.readInt() === 0) {
        let resultStr: string | null = result.readUtf8String()
        return (resultStr == null || resultStr == expName) ? "" : resultStr
    } else return ""
}

globalThis.getSym = (filterName: string, mdName?: string): ModuleSymbolDetails[] | undefined => {
    if (mdName == undefined) {
        return Process.enumerateModules()
            .flatMap(module => module.enumerateSymbols())
            .filter(item => item.name.includes(filterName) || demangleName(item.name).includes(filterName))
    } else {
        const module = Process.findModuleByName(mdName)
        if (!module) {
            logw(`Module '${mdName}' not found...`)
            return undefined
        }
        return module.enumerateSymbols()
            .filter(item => item.name.includes(filterName) || demangleName(item.name).includes(filterName))
    }
}

globalThis.findSym = (filterName: string, imageName: string = "", onlyFunction: boolean = false) => {
    if (filterName == undefined) throw new Error('filterName can not be null ...')
    newLine()
    if (imageName != undefined && imageName.length > 0) {
        if (imageName.includes('*')) {
            Process.enumerateModules().filter(item => item.name.includes(imageName.replace('*', ''))).forEach(i => (iteratorName(i)))
        } else {
            iteratorName(Process.findModuleByName(imageName))
        }
    } else if (imageName != undefined && imageName != "") {
        iteratorName(Process.findModuleByName(imageName))
    } else {
        Process.enumerateModules().forEach(iteratorName)
    }

    function iteratorName(md: Module | null) {
        if (md == null) throw new Error('Module can not be null ...')
        const syms = md.enumerateSymbols()
        const filterSyms = syms.map(item => { return { msd: item, demangeName: demangleName(item.name), rva: item.address.sub(md.base) } })
            .filter(item => item.demangeName.includes(filterName) || item.msd.name.includes(filterName))
            .filter(item => onlyFunction ? item.msd.type == 'function' : true)
            .filter(item => !item.msd.address.isNull())
        if (filterSyms.length == 0) return
        logw(`Found { ${filterSyms.length} / ${syms.length} } in '${md.path}'\n`)
        filterSyms.forEach((item, index) => {
            logd(`[${index}] \t${item.msd.address} -> \t${item.msd.name}`)
            if (item.demangeName.length != 0) logz(`\t\t\t${item.demangeName} | ${item.rva}`)
        })
        newLine()
    }
}

globalThis.sleep = (sec: number) => new NativeFunction(DebugSymbol.fromName("sleep").address, 'pointer', ['int'])(sec)

const _getAddr__mod_init_func = (sectionName: string = "__mod_init_func", moduleName: string = Process.mainModule.name) => {
    return Process.getModuleByName(moduleName).enumerateSections().find(item => item.name.includes(sectionName))
}

globalThis.saveFile = (start: number | NativePointer, size: number, fileName: string = `/tmp/${Date.now()}`) => {
    if (start == null || start == undefined || start == 0) throw new Error("start Address can not be null")
    if (size == null || size == undefined || size == 0) throw new Error("size can not be null")
    const file = new File(fileName, "wb")
    const startPtr = start instanceof NativePointer ? start : ptr(start)
    file.write(startPtr.readByteArray(size)!)
    logd(`MEM ${start} -> ${size} has been saved to ${fileName}`);
}

globalThis.saveModule = (mdName: string) => {
    if (mdName == null || mdName == undefined || mdName.length == 0) throw new Error("mdName can not be null")
    const module = Process.findModuleByName(mdName)
    if (module == null) throw new Error("Module not found")
    saveFile(module.base, module.size, `/tmp/${module.name}`)
}

globalThis.listModules = (filterName: string) => {
    if (filterName == undefined) {
        Process.enumerateModules().forEach(item => logd(JSON.stringify(item)))
    } else {
        Process.enumerateModules().filter(i => i.name.includes(filterName)).forEach(item => logd(JSON.stringify(item)))
    }
}

// ObjC.classes["NIMSDK"]["- registerWithOption:"]
globalThis.trace = (cls: string = "NIMSDK", func: string = "- registerWithOption:", filterlib: string = "AcmeisApp.app") => {
    Interceptor.attach(ObjC.classes[cls][func].implementation, {
        onEnter(args) {
            const instance = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            this.msg = `${cls} ${func} ${instance} ${sel}`
            logw(`\nCalled -> ${this.msg}`)
            const tid = Process.getCurrentThreadId()
            logw(`\nThread ID: ${tid}`)

            const mdmap = new ModuleMap(item => item.path.includes(filterlib))
            logd("↓ Stalker trace ↓\n")
            Stalker.follow(tid, {
                events: {
                    call: true,
                    ret: true
                },
                onReceive: function (events) {
                    const bbs = Stalker.parse(events, {
                        stringify: false,
                        annotate: false
                    });
                    let msg = bbs.flat()
                        .map(item => ptr(item as unknown as string))
                        .filter(item => mdmap.has(item))
                        .map(item => DebugSymbol.fromAddress(item))
                        .map(item => `${item} ${item.address}`)
                        .join('\n')
                    logd(msg)
                }
            })
        },
        onLeave: function (retval) {
            logd("onLeave")
            Stalker.unfollow()
        }
    })
}

// usesage => choose("SBTelephonyManager")
globalThis.choose = (className: string | ObjC.Object | number | NativePointer, callBack?: (item: ObjC.Object) => void | undefined) => {
    if (typeof className == "string") {
        var cls = ObjC.classes[className]
    } else if (className instanceof ObjC.Object) {
        var cls = className
    } else if (typeof className == "number") {
        if (ObjC.api.object_isClass(ptr(className))) {
            var cls = new ObjC.Object(ptr(className))
        } else {
            var cls = new ObjC.Object(ptr(className)).$class
        }
    } else if (className instanceof NativePointer) {
        var cls = new ObjC.Object(className)
    } else throw new Error(`className must be string | ObjC.Object | number | NativePointer`)

    log('\n')
    if (cls == null) throw new Error(`Class '${className}' not found`)
    ObjC.chooseSync(cls).forEach((item, index) => {
        try {
            if (callBack == undefined) {
                let dis = item.toString()
                if (!dis.includes(item.handle.toString())) dis = `${item.handle} -> ${dis}`
                logd(`[ ${index} ] ${dis}\n`)
            } else callBack(item)
        } catch (e) {
            logw(e)
        }
    })
}

// oc print stack 
// if use ObjC.implement to hook, you can use this
export function printObjcStackTrace(message = "Current Objective-C Stack Trace") {
    try {
        const NSThread = ObjC.classes.NSThread
        if (!NSThread) {
            loge("[Frida] NSThread class not found. Cannot print Objective-C stack trace.")
            return
        }
        const callStackSymbols = NSThread.callStackSymbols()

        logw(`\n--- ${message} ---`)
        for (let i = 0; i < callStackSymbols.count(); i++) {
            const symbol = callStackSymbols.objectAtIndex_(i)
            logz(`  ${symbol.toString()}`)
        }
        logz("-------------------------------------------\n")

    } catch (e) {
        loge(`[Frida] Error printing Objective-C stack trace: ${e}`)
    }
}

declare global {
    var ProcessDispTask: any
    var clear: () => void
    var cls: () => void // alias for clear
    var findSym: (filterName: string, imageName?: string, onlyFunction?: boolean) => void
    var hex: (ptr: NativePointer | string | number, len?: number) => void
    var checkPointer: (ptr: NativePointer | number | string | ObjC.Object | ObjC.ObjectMethod, throwErr?: boolean) => NativePointer
    var allocOCString: (str: string) => ObjC.Object
    var allocCString: (str: string) => NativePointer
    // call("method_getImplementation", method)
    // same to ObjC.api.method_getImplementation(method)
    var call: (ptr: NativePointer | number | string | ObjC.Object, ...args: any | NativePointer | ObjC.Object) => NativePointer
    var callOC: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => NativePointer
    var callOcOnMain: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => void
    var lfs: (ptr: NativePointer | string | number) => void
    var xa: (ptr: NativePointer | string | number, count?: number) => void
    var xas: (ptr: NativePointer | string | number, count?: number, split?:string) => string
    var choose: (className: string, callBack?: (item: ObjC.Object) => void | undefined) => void

    var getIvars: (clazz: NativePointer | string | number | ObjC.Object) => Array<{ objClazz: ObjC.Object, handle: NativePointer, name: string, offset: number }>
    var showIvars: (clazz: NativePointer | string | number | ObjC.Object) => void

    var dumpUI: () => void

    var trace: () => void

    var A: (mPtr: ARGM, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord?: boolean) => void
    var d: (mPtr?: ARGM) => void
    var n: (mPtr: ARGM) => void
    var nn: (mPtr: ARGM) => void
    var nnn: () => void
    var D: () => void

    var stk: (mPtr: NativePointer) => void

    var isObjcInstance: (mPtr: NativePointer) => NativePointer
    var addressToMethod: (mPtr: NativePointer | number) => ObjC.ObjectMethod
    var nameToMethod: (name: string) => ObjC.ObjectMethod

    var showAsm: (mPtr: NativePointer, len?: number) => void
    // alias showAsm ( similar to lldb dis )
    var dis: (mPtr: NativePointer, len?: number) => void

    var asOcObj: (mPtr: NativePointer) => ObjC.Object
    var asOcObjtoString: (mPtr: NativePointer) => string
    var asOcString: (mPtr: NativePointer) => void
    var asOcSELtoString: (mPtr: NativePointer) => string

    var demangleName: (expName: string) => string

    var getSym: (filterName: string, mdName?: string) => ModuleSymbolDetails[] | undefined

    var sleep: (sec: number) => void

    var saveFile: (start: number | NativePointer, size: number, fileName?: string) => void
    var saveModule: (mdName: string) => void
    var listModules: (filterName: string) => void

    var raise: (sig: SIGNAL) => void
    var printBacktrace: (ctx: CpuContext) => void
    var getBacktrace: (ctx: CpuContext) => string
}

export enum HK_TYPE {
    FRIDA_ATTACH = 0,
    FRIDA_REP = 1,
    OBJC_REP = 2
}


globalThis.d = detachAll
globalThis.A = attachNative
globalThis.n = nopFunction
globalThis.nn = cancelNop
globalThis.nnn = cancelAllNopedFunction
globalThis.D = () => { d(); nnn() }

globalThis.stk = stk