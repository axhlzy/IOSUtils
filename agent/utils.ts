import { NSUTF8StringEncoding } from './constants.js'
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

globalThis.findSym = (filterName: string, exact: boolean = false, onlyFunction: boolean = false) => {
    Process.enumerateModules()
        .forEach(module => {
            module.enumerateSymbols()
                .filter(symbol => exact ? symbol.name == filterName : symbol.name.includes(filterName))
                .filter(symbol => onlyFunction ? symbol.type == 'function' : true)
                .filter(symbol => !symbol.address.isNull())
                .forEach(symbol => logd(`${symbol.address} <= ${symbol.name}`))
        })
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
        data.bytes(), data.length(), NSUTF8StringEncoding);
    if (s) {
        return s.UTF8String()
    }
    return ""
};

globalThis.lfs = (ptr: NativePointer | string | number, ret: boolean = false) => {
    const mPtr = checkPointer(ptr)
    const obj = new ObjC.Object(mPtr)
    if (obj.$kind != "instance") throw new Error("ivars | can only parse instance")
    showSuperClasses(obj.handle)
    const $clonedIvars: { [name: string]: any } = {}
    const vars = obj.$ivars
    let index: number = 0
    for (const k in vars) {
        try {
            if (vars.hasOwnProperty(k)) {
                const v = vars[k] as Object
                $clonedIvars[k] = bytesToUTF8(v)
                if (ret) continue
                if (v instanceof ObjC.Object) {
                    logd(`[${++index}] ${k}: | ObjC.Object <- ${v.$kind} of ${v.$className} @ ${v.$class.handle}`)
                    logz(`\t${v.handle}`)
                } else if (typeof v == "object") {
                    logd(`[${++index}] ${k}: | ${typeof v}`)
                    logz(`\t${v}`)
                } else {
                    logd(`[${++index}] ${k}: | ${typeof v}`)
                    logz(`\t${$clonedIvars[k]}`)
                }
            }  
        } catch (error) {
            
        }
    }
    if (ret) return $clonedIvars
}

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
                    compile: true
                },
                onReceive: function (events) {
                    const bbs = Stalker.parse(events, {
                        stringify: false,
                        annotate: false
                    });
                    logd("↓ Stalker trace ↓\n")
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
globalThis.nameToMethod = (method:string): ObjC.ObjectMethod=> {
    if (method[1] == '[' && method.endsWith(']')) {
        let methodL = method.slice(2, -1)
        const parts = methodL.split(' ')
        if (parts.length != 2) throw new Error("Invalid format, there should be exactly one space.")
        const className = parts[0]
        const classMethod = `${method[0]} ${parts[1]}`
        return ObjC.classes[className][classMethod]
    } else {
        throw new Error("Invalid format, should start with '+[' / '-[' and end with ']'")
    }
}

globalThis.addressToMethod = (mPtr: NativePointer): ObjC.ObjectMethod => {
    return nameToMethod(DebugSymbol.fromAddress(mPtr).name!)
}

declare global {
    var ProcessDispTask: any
    var clear: () => void
    var cls: () => void // alias for clear
    var findSym: (filterName: string, exact?: boolean, onlyFunction?: boolean) => void
    var hex: (ptr: NativePointer | string | number, len?: number) => void
    var checkPointer: (ptr: NativePointer | number | string | ObjC.Object | ObjC.ObjectMethod, throwErr?: boolean) => NativePointer
    var allocOCString: (str: string) => ObjC.Object
    var allocCString: (str: string) => NativePointer
    var call: (ptr: NativePointer | number | string | ObjC.Object, ...args: any | NativePointer | ObjC.Object) => NativePointer
    var callOC: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => NativePointer
    var callOcOnMain: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => void
    var lfs: (ptr: NativePointer | string | number) => void
    var dumpUI: () => void

    var A: (mPtr: ARGM, mOnEnter?: OnEnterType, mOnLeave?: OnExitType, needRecord?: boolean) => void
    var d: (mPtr?: ARGM) => void
    var n: (mPtr: ARGM) => void
    var nn: (mPtr: ARGM) => void
    var nnn: () => void
    var D: () => void

    var stk: (mPtr: NativePointer) => void

    var isObjcInstance: (mPtr: NativePointer) => NativePointer
    var addressToMethod: (mPtr: NativePointer) => ObjC.ObjectMethod
    var nameToMethod: (name: string) => ObjC.ObjectMethod
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