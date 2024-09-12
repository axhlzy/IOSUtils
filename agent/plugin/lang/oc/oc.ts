export { }

var cacheAllClass: ObjC.Object[] = []

globalThis.cacheAllClass = cacheAllClass

const getCachedClasses = () => {
    if (cacheAllClass.length === 0)
        cacheAllClass = Object.values(ObjC.classes) as ObjC.Object[]
    return cacheAllClass
}

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
                    // const extra = "C: " + (includeParent ? `${getClassFromMethodName(m, supClasses)?.$class.handle}` : '')
                    const extra = ''
                    // instance can parse method address
                    return `[ ${i} ]\t${extra} M: ${obj.$class[m].implementation} | ${m}`
                } catch (error) {
                    // only method names
                    return `[ ${i} ]\t C: ${obj.$class.handle} | ${m}`
                }
            })
            .forEach(item => item.includes('_') ? logz(item) : logd(item))
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

globalThis.m = globalThis.showMethods

declare global {
    var showMethods: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void
    var m: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void // alias for showMethods
    var findMethods: (query: string, className?: string, accurate?: boolean) => void
    var findMethodsByResolver: (query: string) => void
    var findClasses: (query: string) => void

    var cacheAllClass: ObjC.Object[]
} 