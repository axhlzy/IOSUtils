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
        .forEach((m: ApiResolverMatch) => {
            logd(`[ ${count++} ]\t${m.address}\t${m.name}`)
        })
}

globalThis.showMethods = (clsNameOrPtr: number | string | NativePointer, filter: string = '', includeParent: boolean = false) => {
    if (clsNameOrPtr == null)
        throw new Error("classNameOrPtr cannot be null")

    let localPtr: NativePointer = NULL
    if (typeof clsNameOrPtr == "string" && clsNameOrPtr.startsWith("0x"))
        localPtr = ptr(clsNameOrPtr)
    else if (typeof clsNameOrPtr == "number")
        localPtr = ptr(clsNameOrPtr)
    else if (typeof clsNameOrPtr == "string")
        localPtr = ObjC.classes[clsNameOrPtr].$class.handle
    else if (clsNameOrPtr instanceof NativePointer)
        localPtr = clsNameOrPtr

    if (localPtr == NULL)
        throw new Error("classNameOrPtr is not a valid pointer")

    newLine()
    let obj = new ObjC.Object(localPtr)
    logw(`[ ${obj.$className} ] ${obj.$class.handle}`)

    includeParent ? obj.$methods : obj.$ownMethods
        .filter(m => m.includes(filter))
        .map((m, i) => {
            try {
                return `[ ${i} ]\t M: ${ObjC.classes[obj.$className][m].implementation} ${m}`
            } catch (error) {
                return `[ ${i} ]\t C: ${ObjC.classes[obj.$className].handle} ${m}`
            }
        })
        .forEach(logd)
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
    var showMethods: (clsNameOrPtr: number | string | NativePointer) => void
    var findMethods: (query: string, className?: string, accurate?: boolean) => void
    var findMethodsByResolver: (query: string) => void
    var findClasses: (query: string) => void

    var cacheAllClass: ObjC.Object[]

    // alies
    var m: typeof showMethods
} 