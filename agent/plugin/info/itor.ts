export { }

declare global {
    var i: (showAll?: boolean) => void //alias for list images
}

export const list_images = (showAll: boolean = false, countMethods: boolean = false) => {

    const arrMain = getClassNameArrayFromMdPath(Process.mainModule.path)
    const methodsCount = arrMain.map(clsName => ObjC.classes[clsName].$methods.length).reduce((sum, count) => sum + count, 0)
    const methodsMsg = `| METHODS:${methodsCount}`
    loge(`[ - ] \t${Process.mainModule.base} -> ${Process.mainModule.name} | CLS:${arrMain.length} ${methodsMsg}`)
    logz(`\t${Process.mainModule.path}`)

    Process.enumerateModules()
        .map(_md => { return { md: _md, arr: getClassNameArrayFromMdPath(_md.path) } })
        .filter(item => showAll ? true : item.arr.length != 0)
        .forEach((item, index) => {
            let methodsMsg = ``
            if (countMethods) {
                const methodsCount = item.arr.map(clsName => ObjC.classes[clsName].$methods.length).reduce((sum, count) => sum + count, 0)
                methodsMsg = `| METHODS:${methodsCount}`
            }
            logd(`[ ${index} ] \t${item.md.base} -> ${item.md.name} | CLS:${item.arr.length} ${methodsMsg}`)
            logz(`\t${item.md.path}`)
        })
}

function getClassNameArrayFromMdPath(path: string): Array<string> {
    const free_addr = Module.findExportByName(null, 'free')!
    const free = new NativeFunction(free_addr, 'void', ['pointer'])

    const objc_copyClassNamesForImage_addr = Module.findExportByName(null, 'objc_copyClassNamesForImage')!
    const copyClassNamesForImage = new NativeFunction(objc_copyClassNamesForImage_addr, 'pointer', ['pointer', 'pointer'])

    const tempMem = Memory.alloc(Process.pointerSize)
    let classNames: Array<string> = new Array()
    tempMem.writeUInt(0)

    try {
        const pClasses = copyClassNamesForImage(Memory.allocUtf8String(path), tempMem)
        classNames = new Array<string>(tempMem.readUInt())
        if (pClasses.readUInt() != 0) {
            for (var i = 0; i < tempMem.readUInt(); i++) {
                const pClassName = pClasses.add(i * Process.pointerSize).readPointer()
                classNames.push(`${pClassName.readUtf8String()}`)
            }
            free(pClasses)
        }
    } catch { }

    return classNames
}

globalThis.i = list_images