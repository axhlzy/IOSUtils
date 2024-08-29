export { }

globalThis.clear = () => console.log('\x1Bc')

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

    public setMax(max: number){
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

declare global {
    var clear: () => void
    var ProcessDispTask: any
}
