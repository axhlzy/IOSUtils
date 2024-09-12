import { NSUTF8StringEncoding } from './constants.js'
import { NSString } from './types.js'
import './types.js'

export { }

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

globalThis.checkPointer = (ptr: NativePointer | number | string | ObjC.Object, throwErr: boolean = true): NativePointer => {
    let mPtr: NativePointer = NULL
    if (typeof ptr === 'string') {
        if (ptr.startsWith('0x')) mPtr = new NativePointer(parseInt(ptr, 16))
        else {
            mPtr = DebugSymbol.fromName(ptr).address
            if (mPtr.isNull()) mPtr = ObjC.classes[ptr].handle
            if (mPtr.isNull()) throw new Error(`Invalid pointer <- cannot find ${ptr}`)
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
    return ObjC.classes["NSString"]["+ stringWithUTF8String:"](Memory.allocUtf8String(str))
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
globalThis.call = (ptr: NativePointer, ...args):NativePointer => {
    try {
        // logd(`Number of arguments: ${args.length}`)
        // logd(`Arguments: ${args}`)
        const argsStr = args.map(arg => typeof arg === 'number' ? `"pointer"` : `"pointer"`).join(', ') // All types are treated as pointer
        const func = eval(`new NativeFunction(new NativePointer(${checkPointer(ptr)}), 'pointer', [ ${argsStr} ])`)
        if (typeof func !== 'function') throw new Error("Error while Created NativeFunction")
        return func(...args.map(item => checkPointer(item as any)))
    } catch (error) {
        loge(`Error during call: \n\t${error}`)
        // throw error
        return NULL
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
    }
    if (ret) return $clonedIvars
}

declare global {
    var ProcessDispTask: any
    var clear: () => void
    var findSym: (filterName: string, exact?: boolean, onlyFunction?: boolean) => void
    var hex: (ptr: NativePointer | string | number, len?: number) => void
    var checkPointer: (ptr: NativePointer | number | string | ObjC.Object, throwErr?: boolean) => NativePointer
    var allocOCString: (str: string) => ObjC.Object
    var call: (ptr: NativePointer, args: any[]) => void
    var callOC: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any) => NativePointer
    var callOcOnMain: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any) => void
    var lfs: (ptr: NativePointer | string | number) => void
    var dumpUI: () => void
}
