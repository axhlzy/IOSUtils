import { HK_TYPE } from "../../utils.js"

export { }

class Breaker {

    // ref function ptr => IMP
    public static attachImpl(mPtr: NativePointer | number | string, defaultArgsC: number = 4) {
        new objc_method(addressToMethod(checkPointer(mPtr) as NativePointer).handle).hook(HK_TYPE.FRIDA_REP, true, defaultArgsC)
    }

    //  ref Method => Method
    public static attachMethod(mPtr: NativePointer | number | string, force: boolean = false) {
        new objc_method(mPtr).hook(HK_TYPE.OBJC_REP, true, 6, force)
    }

    // ref Class / ObjC.Object
    public static attachClass(mPtr: NativePointer | number | string | ObjC.Object, filterMethodNameStr: string = '', force: boolean = false) {
        if (typeof mPtr == "string" && mPtr.startsWith("0x")) mPtr = ptr(mPtr)
        const localPtr: NativePointer = checkPointer(mPtr)
        const localObj = new ObjC.Class(localPtr) // ref Class
        Breaker.itorMethod(localObj, (method: ObjC.ObjectMethod, _impl) => {
            const methodName = `${ObjC.selectorAsString(method.selector)}`
            if (methodName.includes(filterMethodNameStr)) Breaker.attachMethod(method.handle, force)
            // else logz(`${method.implementation} -> ${methodName} | Warn: filter method name`)
        })
    }

    public static itorMethod(obj: ObjC.Object, callback: (method: ObjC.ObjectMethod, impl: NativePointer) => void) {
        obj.$ownMethods.forEach(m => {
            let method: ObjC.ObjectMethod
            let impl: NativePointer
            try {
                method = obj[m] as ObjC.ObjectMethod
                try {
                    impl = method.implementation
                } catch (error) {
                    impl = OC_Hook_Status.getNewImplFromOCMethod(method)!
                }
            } catch (error) {
                const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                const method_ptr = call("class_getInstanceMethod", obj, selector)
                method = new ObjC.Object(method_ptr) as any
                impl = call("method_getImplementation", method)
            }
            callback(method, impl)
        })
    }

    public static attachMethodsByFilter(filterName: string, filterClass: string, type: ApiResolverType = "objc") {
        if (filterName == undefined || filterName.length == 0) throw new Error('Need args[0] filterStr: string')
        let filter: string = filterName
        if (filterClass != undefined && !filterName.includes("[")) {
            filter = `*[${filterClass} *${filterName}*]`
        } else if (!filterName.includes("[")) {
            filter = `*[* *${filterName}*]`
        }
        new ApiResolver(type).enumerateMatches(filter).forEach(item => {
            logd(item.address + ' -> ' + item.name)
            try {
                Breaker.attachImpl(item.name)
            } catch (error) {
                loge(error)
            }
        })
    }
}

declare global {
    var B: (mPtr: NativePointer | number | string | ObjC.Object, filter?: string) => void
    var b: (mPtr: NativePointer | number | string) => void

    var BF: (filterStr: string, type: ApiResolverType) => void
}

globalThis.b = (mPtr: NativePointer | number | string) => { Breaker.attachMethod(mPtr, true) }
globalThis.B = Breaker.attachClass

globalThis.BF = Breaker.attachMethodsByFilter