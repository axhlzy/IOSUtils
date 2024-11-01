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
    logw(`\nDisplay methods of ${obj.$className} @ ${obj.$class.handle}`)
    try {
        const debugSym = DebugSymbol.fromAddress(obj.$class.handle)
        const md = Process.findModuleByName(debugSym.moduleName!)
        logz(`${debugSym.name} IN ${debugSym.moduleName} [ ${md?.path} ${ptr(md?.size!)} ]`)
    } catch (error) { }

    showSuperClasses(obj)

    // const supClasses = getSuperClasses(obj)

    let count: number = 0
    {
        (() => { return includeParent ? obj.$methods : obj.$ownMethods })()
            .filter(m => filter.length == 0 ? true : m.includes(filter))
            .sort((i1, i2) => i2.localeCompare(i1))
            .map((m, i) => {
                count = i
                try {
                    // !todo 在 includeParent 启用的时候 分组展示类方法
                    // const extra = "C: " + (includeParent ? `${getClassFromMethodName(m, supClasses)?.$class.handle}` : '')
                    const _extra = ''
                    // class methods
                    const method = obj.$class[m]
                    const impl = method.implementation
                    const md = Process.findModuleByAddress(impl)
                    let extraDes: string = "-> "
                    try {
                        // after objc.implement, An error will be triggered here.
                        const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                        extraDes += `${rva} `
                    } catch (error) {
                        extraDes = ''
                    }
                    return `[ ${i} ]\t M: ${ptr(method)} -> ${impl} ${extraDes} | ${m}`
                } catch (error) {
                    // instance methods
                    const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                    const method = call("class_getInstanceMethod", obj, selector)
                    const impl = call("method_getImplementation", method)
                    const md = Process.findModuleByAddress(impl)
                    let extraDes: string = "-> "
                    try {
                        // after objc.implement, An error will be triggered here.
                        const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                        extraDes += `${rva} `
                    } catch (error) {
                        extraDes = ''
                    }
                    return `[ ${i} ]\t M: ${method} -> ${impl} ${extraDes}| ${m}`
                }
            })
            .forEach((item, i) => item.includes(' _') ? logz(item) : logd(item))
    }
    logn(`\n{ F:${count + 1} / A:${obj.$methods.length} }\n`)
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
            .map((m, i) => {
                try {
                    // class methods
                    const method = cls.$class[m]
                    const impl = method.implementation // throw error while type of class is instance
                    const md = Process.findModuleByAddress(impl)
                    let extraDes: string = "-> "
                    try {
                        // after objc.implement, An error will be triggered here.
                        const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                        extraDes += `${rva} `
                    } catch (error) {
                        extraDes = ''
                    }
                    return `[ ${i} ]\t M: ${ptr(method)} -> ${impl} ${extraDes} | ${m}`
                } catch (error) {
                    // instance methods
                    const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                    const method = call("class_getInstanceMethod", cls, selector)
                    const impl = call("method_getImplementation", method)
                    const md = Process.findModuleByAddress(impl)
                    let extraDes: string = "-> "
                    try {
                        // after objc.implement, An error will be triggered here.
                        const rva = String(impl.sub(md?.base!)).padEnd(11, ' ')
                        extraDes += `${rva} `
                    } catch (error) {
                        extraDes = ''
                    }
                    return `[ ${i} ]\t M: ${method} -> ${impl} ${extraDes} | ${m}`
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
            const md = Process.findModuleByName(cls.$moduleName)
            logz(`\t${md?.base} ${ptr(md?.size!)} \t ${cls.$moduleName}`)
        })

    newLine()
}

globalThis.getSuperClasses = (ptr: NativePointer | number | string | ObjC.Object): Array<ObjC.Object> => {
    const obj = new ObjC.Object(checkPointer(ptr))
    let cls_itor: ObjC.Object = obj
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

globalThis.showMethod = (method: number | string | NativePointer, extName?: string) => {

    // // struct objc_method_description {
    // //     SEL _Nullable name;               /**< The name of the method */
    // //     char * _Nullable types;           /**< The types of the method arguments */
    // // };
    // class objc_method_description {
    //     name: NativePointer
    //     types: NativePointer
    //     constructor(public mPtr: NativePointer) {
    //         this.name = mPtr
    //         this.types = mPtr.add(Process.pointerSize)
    //     }
    //     public toString() {
    //         return `name: ${this.name.readPointer().readCString()} types: ${this.types.readPointer().readCString()}`
    //     }
    // }

    let localM: NativePointer = NULL
    try {
        localM = checkPointer(method)
    } catch (error) {
        // try use ApiResolver to find (methodName)
        if (typeof method == "string") {
            let found: ApiResolverMatch[]
            if (method.includes('[')) {
                found = new ApiResolver("objc").enumerateMatches(method)
            } else {
                found = new ApiResolver("objc").enumerateMatches(`*[* ${method}]`)
            }
            if (found != undefined && found != null && found.length != 0) {
                found.forEach(item => showMethod(nameToMethod(item.name).handle, item.name))
            } else {
                throw new Error(`Not Found -> ${method}`)
            }
            return
        } else throw error
    }

    logs(getLine(60, '-'))

    logd(`Address\t\t\t->\t${localM}`)

    // OBJC_EXPORT SEL _Nonnull method_getName(Method _Nonnull m)
    const name = call("method_getName", localM).readCString() as string
    logd(`Name\t\t\t->\t${name} ${extName == undefined ? '' : ` | ${extName}`}`)

    const argsCount = call("method_getNumberOfArguments", localM).toInt32()
    logd(`NumberOfArguments\t->\t${argsCount}`)

    // OBJC_EXPORT const char * _Nullable method_getTypeEncoding(Method _Nonnull m) 
    const typeEncoding = call("method_getTypeEncoding", localM).readCString()
    logd(`TypeEncoding\t\t->\t${typeEncoding}`)

    // alias name + types ↓
    // const description = new objc_method_description(call("method_getDescription", localM))
    // logd(`Description\t\t->\t${description}`)

    // OBJC_EXPORT IMP _Nonnull method_getImplementation(Method _Nonnull m) 
    const implementation = call("method_getImplementation", localM) as NativePointer
    let extraDes: string
    try {
        const rva = implementation.sub(Process.findModuleByAddress(implementation)?.base!)
        extraDes = `| ${rva} `
        logd(`Implementation\t\t->\t${implementation} ${extraDes}`)
    } catch (error) {
        // already modify
        extraDes = ''
        logz(`Implementation\t\t->\t${implementation} ${extraDes}`)
    }

    const pk = getArgsAndRet(localM)
    logd(`ReturnType`)
    logd(`\tret: \t\t${pk.ret} - ${parseType(pk.ret)}`)
    logd('ArgumentTypes')
    pk.args.forEach((item, index) => logd(`\targs[${index}]:\t${item} - ${parseType(item)}`))
}

export const packArgs = (arg: NativePointer, type: string): string => {
    // todo
    if (type == "string") return arg.readCString() == null ? "" : arg.readCString()!
    if (type == "class") return new ObjC.Object(arg).toString()
    if (type == "object") return new ObjC.Object(arg).toString()
    if (type == "selector") return ObjC.selectorAsString(arg)
    if (type == "void") return ''
    else return arg.toString()
}

export const getArgsAndRet = (method: NativePointer): { ret: string, args: Array<string> } => {

    let packArgsAndRet: { ret: string, args: Array<string> } = { ret: "", args: [] }

    // OBJC_EXPORT char * _Nonnull method_copyReturnType(Method _Nonnull m) 
    // OBJC_EXPORT void method_getReturnType(Method _Nonnull m, char * _Nonnull dst, size_t dst_len) 
    const dst_len: number = 0x20
    const dst_ptr: NativePointer = Memory.alloc(dst_len)
    call("method_getReturnType", method, dst_ptr, dst_len)
    const type: string = dst_ptr.readCString()!
    packArgsAndRet.ret = type

    dst_ptr.writeByteArray(Array.from(new Uint8Array(dst_len)))

    // OBJC_EXPORT char * _Nullable method_copyArgumentType(Method _Nonnull m, unsigned int index) 
    // OBJC_EXPORT void method_getArgumentType(Method _Nonnull m, unsigned int index, char * _Nullable dst, size_t dst_len) 
    for (let i = 0; i < call("method_getNumberOfArguments", method).toInt32(); i++) {
        try {
            dst_ptr.writeByteArray(Array.from(new Uint8Array(dst_len)))
            call("method_getArgumentType", method, i, dst_ptr, dst_len)
            packArgsAndRet.args[i] = dst_ptr.readCString()!
        } catch (error) {
            if (i == 0) packArgsAndRet.args[0] = "@"
            else throw error
        }
    }
    return packArgsAndRet
}

/**
 * parse type to string 
 * @param typeStr type string
 * @param toDisplay disp(default) or fridaType
 * @returns 
 */
const parseType = (typeStr: string | null, toDisplay: boolean = true): string => {

    const idByAlias: Record<string, string> = {
        'c': 'char',
        'i': 'int',
        's': 'int16',
        'q': 'int64',       // long
        'C': 'uchar',
        'I': 'uint',
        'S': 'uint16',
        'Q': 'uint64',
        'f': 'float',
        'd': 'double',
        'B': 'bool',        // BOOL
        'b': 'bool',
        'v': 'void',
        '*': 'string',      // char *
        '@': 'object',      // id
        '@?': 'block',
        '#': 'class',       // Class
        ':': 'selector',    // SEL
        '^v': 'pointer'     // void *
    }

    const fridaTypeExt: Record<string, string> = {
        'BOOL': 'bool',
        'object': 'pointer',
        'block': 'pointer',
        'class': 'pointer',
        'selector': 'pointer'
    }

    if (typeStr == null || typeStr == undefined) return ''

    if (toDisplay) {
        // to display
        if (typeStr in idByAlias) return idByAlias[typeStr]
        if (typeStr.startsWith("{")) return "struct"
        // throw new Error(`Type case not impl ? ${typeStr}`)
        return `${typeStr} <- parse error`
    } else {
        // to frida type
        if (typeStr in idByAlias) {
            const ret = idByAlias[typeStr]
            const ret_case = fridaTypeExt[ret]
            return ret_case == undefined ? ret : ret_case
        }
        // throw new Error(`Type case not impl ? ${typeStr}`)
        return `pointer`
    }
}

globalThis.getFields = (cls: number | string | NativePointer): Array<string> => {
    const localCls = checkPointer(cls)
    const ObjCls = new ObjC.Object(localCls)
    let fields: Array<string> = new Array()
    for (const k in ObjCls.$ivars) { fields.push(k) }
    return fields
}

// cls can be instanceof ObjC.ObjC or Class(OC MetaClass)
const listFields = (cls: number | string | NativePointer) => getFields(cls).forEach(logd)

globalThis.f = listFields

/**
 * get method impl
 * @param className 
 * @param methodName 
 * @returns impl / not Method
 */
globalThis.lookupMethod = (className: string, methodName: string): NativePointer => {
    // this two api available ↓
    try {
        // (void*)class_lookupMethod((Class)NSClassFromString(@"Counter"), (SEL)NSSelectorFromString(@"setTestStr:"));
        const clz = call("NSClassFromString", allocOCString(className))
        if (clz.isNull()) throw new Error(`class ${className} not found`)

        const sel = call("NSSelectorFromString", allocOCString(methodName))
        if (sel.isNull()) throw new Error(`error: get selector ${methodName}`)

        const impl = call("class_lookupMethod", clz, sel)
        if (impl.isNull()) throw new Error(`class ${className} method ${methodName} not found`)
        return impl
    } catch (error) {
        // OBJC_EXPORT IMP _Nullable class_getMethodImplementation(Class _Nullable cls, SEL _Nonnull name) 
        const clz = call("objc_getClass", allocCString(className))
        if (clz.isNull()) throw new Error(`class ${className} not found`)

        const sel = call("NSSelectorFromString", allocOCString(methodName))
        if (sel.isNull()) throw new Error(`error: get selector ${methodName}`)

        const impl = call("class_getMethodImplementation", clz, sel)
        if (impl.isNull()) throw new Error(`class ${className} method ${methodName} not found`)
        return impl
    }
}

const watch_getClass = () => {
    // todo
    // OBJC_EXPORT void objc_setHook_getClass(objc_hook_getClass _Nonnull newValue, objc_hook_getClass _Nullable * _Nonnull outOldValue)
}

declare global {
    var cacheAllClass: ObjC.Object[]
    var showMethods: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void
    var m: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void // alias for showMethods
    var f: (clsNameOrPtr: number | string | NativePointer) => void
    var getFields: (cls: number | string | NativePointer) => Array<string>
    var showMethod: (method: number | string | NativePointer, extName?: string) => void
    var findMethods: (query: string, className?: string, accurate?: boolean) => void
    var findMethodsByResolver: (query: string) => void
    var findClasses: (query: string) => void

    var lookupMethod: (className: string, methodName: string) => NativePointer

    var showSuperClasses: (ptr: NativePointer | number | string | ObjC.Object) => void
    var getSuperClasses: (ptr: NativePointer | number | string | ObjC.Object) => Array<ObjC.Object>
    var showSubClasses: (ptr: NativePointer | number | string | ObjC.Object) => void
}


globalThis.showSuperClasses = showSuperClasses
globalThis.getSuperClasses = getSuperClasses
globalThis.showSubClasses = showSubClasses