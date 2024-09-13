export { }

var cacheAllClass: ObjC.Object[] = []

globalThis.cacheAllClass = cacheAllClass

const getCachedClasses = () => {
    if (cacheAllClass.length === 0)
        cacheAllClass = Object.values(ObjC.classes) as ObjC.Object[]
    return cacheAllClass
}

// findMethodsByResolver("-[* *Jail*]")
// findMethodsByResolver("-[NSString *stringWith*]")
globalThis.findMethodsByResolver = (query: string) => {
    if (query == null)
        throw new Error("query cannot be null")
    let count: number = 0
    new ApiResolver("objc")
        .enumerateMatches(query)
        .forEach((m: ApiResolverMatch) => logd(`[ ${count++} ]\t${m.address}\t${m.name}`))
}

const getClassFromMethodName = (name: string, filterClass: Array<ObjC.Object>): ObjC.Object | undefined => {
    let cls: ObjC.Object
    for (let i = 0; i < filterClass.length; i++) {
        cls = filterClass[i]
        if (cls[name]) return cls
    }
}

globalThis.showMethods = (clsNameOrPtr: number | string | NativePointer, filter: string = '', includeParent: boolean = false) => {
    const obj = new ObjC.Object(checkPointer(clsNameOrPtr))
    logw(`\n[ ${obj.$className} ] ${obj.handle} <- cls:${obj.$class.handle}`)

    showSuperClasses(obj)

    // const supClasses = getSuperClasses(obj)

    {
        (() => { return includeParent ? obj.$methods : obj.$ownMethods })()
            .filter(m => filter.length == 0 ? true : m.includes(filter))
            .sort((i1, i2) => i2.localeCompare(i1))
            .map((m, i) => {
                try {
                    // !todo 在 includeParent 启用的时候 分组展示类方法
                    // const extra = "C: " + (includeParent ? `${getClassFromMethodName(m, supClasses)?.$class.handle}` : '')
                    const extra = ''
                    // class methods
                    const method = obj.$class[m]
                    const impl = method.implementation
                    const md = Process.findModuleByAddress(impl)
                    const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                    return `[ ${i} ]\t M: ${ptr(method)} -> ${impl} -> ${rva} | ${m}`
                } catch (error) {
                    // instance methods
                    const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                    const method = call("class_getInstanceMethod", obj, selector)
                    const impl = call("method_getImplementation", method)
                    const md = Process.findModuleByAddress(impl)
                    const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                    return `[ ${i} ]\t M: ${method} -> ${impl} -> ${rva} | ${m}`

                    // 
                }
            })
            .forEach(item => item.includes(' _') ? logz(item) : logd(item))
    }
    newLine()
}

globalThis.findMethods = (query: string, className?: string, accurate = false) => {
    if (query == null)
        throw new Error("query cannot be null")

    let count: number = 0
    if (!className) {
        getCachedClasses().forEach(cls => ItorClassMethods(cls, query, accurate))
    } else {
        ItorClassMethods(ObjC.classes[className], query, accurate)
    }
    newLine()

    function ItorClassMethods(cls: ObjC.Object, query: string, accurate: boolean) {
        const methods = cls.$methods.filter((m) => accurate ? m == query : m.includes(query))
        if (methods.length != 0)
            logw(`\n[!] ${cls.handle} | ${methods.length} | ${cls.$className} \n`)
        methods
            .map(m => {
                try {
                    return `M: ${cls[m].implementation} ${m}`
                } catch (error) {
                    return `C: ${cls.handle} ${m}`
                }
            })
            .sort((a, b) => b[0].localeCompare(a[0]))
            .map(m => `[ ${count++} ]\t${m}`)
            .forEach(logd)
    }
}

globalThis.findClasses = (query: string, accurate: boolean = false) => {
    if (query == null)
        throw new Error("query cannot be null")

    newLine()
    let count: number = 0

    // 不全
    // ObjC.enumerateLoadedClasses({
    //     onMatch(name: string, owner: string) {
    //         if (accurate ? name == query : name.includes(query))
    //             logd(`[ ${count++} ] ${ObjC.classes[name].$class.handle} ${name} ${owner}`)
    //     },
    //     onComplete() {
    //         logw(`\n[findClasses] onComplete | [ ${count} ]\n`)
    //     }
    // })

    getCachedClasses()
        .filter(cls => accurate ? cls.$className == query : cls.$className.includes(query))
        .forEach(cls => {
            logd(`[ ${count++} ]\t${cls.$class.handle}  ${cls.$className}`)
            let md = Process.findModuleByName(cls.$moduleName)
            logz(`\t${md?.base} ${ptr(md?.size!)} \t ${cls.$moduleName}`)
        })

    newLine()
}


globalThis.getSuperClasses = (ptr: NativePointer | number | string | ObjC.Object): Array<ObjC.Object> => {
    const obj = new ObjC.Object(checkPointer(ptr))
    let cls_itor = obj.$class
    let arr = [cls_itor]
    while (true) {
        try {
            if (cls_itor.isNull() || cls_itor.handle.isNull()) break
            cls_itor = cls_itor.$superClass
            if (cls_itor != null) arr.push(cls_itor)
        } catch (error) {
            break
        }
    }
    return arr
}

const showSuperClasses = (ptr: NativePointer | number | string | ObjC.Object) => {
    const arr = getSuperClasses(checkPointer(ptr))
    let disp: string = ''
    try {
        for (let i = 0; i < arr.length; i++) {
            disp += arr[i].$className
            disp += ` ( ${arr[i].$class.handle} ) `
            if (i < arr.length - 1) disp += ' -> '
        }
    } catch (error) {
        // ...
    }
    logd(`\n${disp}\n`)
}

const showSubClasses = (ptr: NativePointer | number | string | ObjC.Object) => {
    const cur = new ObjC.Object(checkPointer(ptr))
    logw(`\nDisplay sub classes of ${cur.$className} @ ${cur.$class.handle} \n`)
    getCachedClasses()
        .filter(item => {
            const sup = item.$superClass
            if (sup == undefined || sup == null) return false
            return sup.equals(cur.$class)
        })
        .sort((a, b) => a.$className.localeCompare(b.$className))
        .forEach((item, index) => {
            const disp = `[ ${index} ]\t${item.$class.handle} -> ${item.$className}`
            item.$className.startsWith('_') ? logz(disp) : logd(disp)
        })
    newLine()
}

globalThis.m = globalThis.showMethods

declare global {
    var showMethods: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void
    var m: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void // alias for showMethods
    var findMethods: (query: string, className?: string, accurate?: boolean) => void
    var findMethodsByResolver: (query: string) => void
    var findClasses: (query: string) => void

    var cacheAllClass: ObjC.Object[]

    var showSuperClasses: (ptr: NativePointer | number | string | ObjC.Object) => void
    var getSuperClasses: (ptr: NativePointer | number | string | ObjC.Object) => Array<ObjC.Object>

    var showSubClasses: (ptr: NativePointer | number | string | ObjC.Object) => void
}


globalThis.showSuperClasses = showSuperClasses
globalThis.getSuperClasses = getSuperClasses

globalThis.showSubClasses = showSubClasses