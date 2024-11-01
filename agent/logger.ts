export enum LogColor {
    WHITE = 0, RED = 1, YELLOW = 3,
    C31 = 31, C32 = 32, C33 = 33, C34 = 34, C35 = 35, C36 = 36,
    C41 = 41, C42 = 42, C43 = 43, C44 = 44, C45 = 45, C46 = 46,
    C90 = 90, C91 = 91, C92 = 92, C93 = 93, C94 = 94, C95 = 95, C96 = 96, C97 = 97,
    C100 = 100, C101 = 101, C102 = 102, C103 = 103, C104 = 104, C105 = 105, C106 = 106, C107 = 107
}

export class Logger {

    private static linesMap = new Map()
    private static colorEndDes: string = "\x1b[0m"
    private static colorStartDes = (color: LogColor): string => `\x1b[${color as number}m`

    static LOGW = (msg: any): void => Logger.LOG(msg, LogColor.YELLOW)
    static LOGE = (msg: any): void => Logger.LOG(msg, LogColor.RED)
    static LOGG = (msg: any): void => Logger.LOG(msg, LogColor.C32)
    static LOGD = (msg: any): void => Logger.LOG(msg, LogColor.C36)
    static LOGN = (msg: any): void => Logger.LOG(msg, LogColor.C35)
    static LOGO = (msg: any): void => Logger.LOG(msg, LogColor.C33)
    static LOGP = (msg: any): void => Logger.LOG(msg, LogColor.C34)
    static LOGM = (msg: any): void => Logger.LOG(msg, LogColor.C92)
    static LOGH = (msg: any): void => Logger.LOG(msg, LogColor.C95)
    static LOGS = (msg: any): void => Logger.LOG(msg, LogColor.C96)
    static LOGZ = (msg: any): void => Logger.LOG(msg, LogColor.C90)

    static LOGLL = (msg: any): void => Logger.LOG(msg, LogColor.C100)
    
    static LOGJSON = (obj: any, type: LogColor = LogColor.C36, space: number = 1): void => Logger.LOG(JSON.stringify(obj, null, space), type)

    private static logL = console.log

    static LOG = (str: any, type: LogColor = LogColor.WHITE): void => {
        switch (type) {
            case LogColor.WHITE: Logger.logL(str); break
            case LogColor.RED: console.error(str); break
            case LogColor.YELLOW: console.warn(str); break
            default: Logger.logL("\x1b[" + type + "m" + str + "\x1b[0m"); break
        }
    }
    static printLogColors = (): void => {
        let str = "123456789"
        Logger.logL(`\n${getLine(16)}  listLogColors  ${getLine(16)}`)
        for (let i = 30; i <= 37; i++) {
            Logger.logL(`\t\t${Logger.colorStartDes(i)} C${i}\t${str} ${Logger.colorEndDes}`)
        }
        Logger.logL(getLine(50))
        for (let i = 40; i <= 47; i++) {
            Logger.logL(`\t\t${Logger.colorStartDes(i)} C${i}\t${str} ${Logger.colorEndDes}`)
        }
        Logger.logL(getLine(50))
        for (let i = 90; i <= 97; i++) {
            Logger.logL(`\t\t${Logger.colorStartDes(i)} C${i}\t${str} ${Logger.colorEndDes}`)
        }
        Logger.logL(getLine(50))
        for (let i = 100; i <= 107; i++) {
            Logger.logL(`\t\t${Logger.colorStartDes(i)} C${i}\t${str} ${Logger.colorEndDes}`)
        }
        Logger.logL(getLine(50))
    }

    // log(chalk.red("this"), chalk.blue("is"), chalk.green("a"), chalk.yellow("test"))
    // chalk.bold chalk.rgb 在 frida 这里不好使
    // static logFormart = (...text: chalk.Chalk[] | string[]) => logL(...text)
    static getLine = (length: number, fillStr: string = "-") => {
        if (length == 0) return ""
        let key = length + "|" + fillStr
        if (Logger.linesMap.get(key) != null) return Logger.linesMap.get(key)
        for (var index = 0, tmpRet = ""; index < length; index++) tmpRet += fillStr
        Logger.linesMap.set(key, tmpRet)
        return tmpRet
    }

    // build a text with color (use LOG to print)
    static getTextFormart = (text: string, color: LogColor = LogColor.WHITE, fillStr: string = " ", length: number = -1, center: boolean = false): string => {
        if (text == undefined) text = ""
        if (length == -1) length = text.length
        let ret = Logger.colorStartDes(color)
        let fillLength = length - text.length
        if (fillLength > 0) {
            let left = Math.floor(fillLength / 2)
            let right = fillLength - left
            if (center) {
                left = right
            }
            ret += getLine(left, fillStr) + text + getLine(right, fillStr)
        } else {
            ret += text
        }
        ret += Logger.colorEndDes
        return ret
    }

    static callOnce<T extends Function>(func: T): T {
        let called = false
        return ((...args: any[]) => {
            if (!called) {
                called = true
                return func(...args)
            }
        }) as unknown as T
    }
}

declare global {
    var log: (str: any, type?: LogColor) => void
    // var LOGS: (str: string, colorDescription: [number, number, LogColor][]) => void
    var logw: (msg: any) => void // LogColor.YELLOW
    var loge: (msg: any) => void // LogColor.RED
    var logd: (msg: any) => void // LogColor.C36
    var logn: (msg: any) => void // LogColor.C35
    var logg: (msg: any) => void // LogColor.C32
    var logo: (msg: any) => void // LogColor.C33
    var logp: (msg: any) => void // LogColor.C33
    var logp: (msg: any) => void // LogColor.C92
    var logh: (msg: any) => void // LogColor.C92
    var logm: (msg: any) => void // LogColor.C95
    var logs: (msg: any) => void // LogColor.C96
    var logz: (msg: any) => void // LogColor.C90
    var logl: (msg: any) => void // LogColor.C102
    var LOGJSON: (obj: any, type?: LogColor, lines?: number) => void
    var newLine: (lines?: number) => void
    var getLine: (length: number, fillStr?: string) => string
    var printLogColors: () => void
    var TFM: (text: string, color?: LogColor, fillStr?: string, length?: number, center?: boolean) => string
    var LogColor: any
}

globalThis.log = Logger.LOG
globalThis.logw = Logger.LOGW
globalThis.loge = Logger.LOGE
globalThis.logg = Logger.LOGG
globalThis.logd = Logger.LOGD
globalThis.logn = Logger.LOGN
globalThis.logo = Logger.LOGO
globalThis.logp = Logger.LOGP
globalThis.logh = Logger.LOGH
globalThis.logm = Logger.LOGM
globalThis.logz = Logger.LOGZ
globalThis.logs = Logger.LOGS
globalThis.logl = Logger.LOGLL
globalThis.LOGJSON = Logger.LOGJSON
globalThis.getLine = Logger.getLine
globalThis.printLogColors = Logger.printLogColors
globalThis.newLine = (lines: number = 1) => Logger.LOG(getLine(lines, "\n"))
globalThis.LogColor = LogColor
// globalThis.log = logFormart // alias log <= logFormart
