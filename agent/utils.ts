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

// new ObjC.selector("xxx") === call("NSSelectorFromString", allocOCString("xxx"))

globalThis.call = (ptr: NativePointer, ...args) => {
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
    }
}

declare global {
    var ProcessDispTask: any
    var clear: () => void
    var findSym: (filterName: string, exact?: boolean, onlyFunction?: boolean) => void
    var hex: (ptr: NativePointer | string | number, len?: number) => void
    var checkPointer: (ptr: NativePointer | number | string | ObjC.Object, throwErr?: boolean) => NativePointer
    var allocOCString: (str: string) => ObjC.Object
    var call: (ptr: NativePointer, args: any[]) => void
}
