import { HK_TYPE } from "../../utils.js"

export { }

class Breaker {

    // ref function ptr => IMP
    public static attachImpl(mPtr: NativePointer | number | string, defaultArgsC: number = 4) {
        new objc_method(addressToMethod(checkPointer(mPtr) as NativePointer).handle).hook(HK_TYPE.FRIDA_REP, true, defaultArgsC)
    }

    //  ref Method => Method
    public static attachMethod(mPtr: NativePointer | number | string) {
        new objc_method(mPtr).hook(HK_TYPE.OBJC_REP, true)
    }

    // ref Class / ObjC.Object
    public static attachClass(mPtr: NativePointer | number | string | ObjC.Object, filterStr: string = '') {
        const localPtr: NativePointer = checkPointer(mPtr)
        const localObj = new ObjC.Class(localPtr) // ref Class
        Breaker.itorMethod(localObj, (method:ObjC.ObjectMethod, _impl) => {
            const methodName = `${ObjC.selectorAsString(method.selector)}`
            if (methodName.includes(filterStr)) Breaker.attachMethod(method.handle)
            // else logz(`${method.implementation} -> ${methodName} | Warn: filter method name`)
        })
    }

    public static itorMethod(obj: ObjC.Object, callback: (method: ObjC.ObjectMethod, impl: NativePointer) => void) {
        obj.$ownMethods.forEach(m => {
            let method: ObjC.ObjectMethod
            let impl: NativePointer
            try {
                method = obj[m] as ObjC.ObjectMethod
                impl = method.implementation
            } catch (error) {
                const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                const method_ptr = call("class_getInstanceMethod", obj, selector)
                method = new ObjC.Object(method_ptr) as any
                impl = call("method_getImplementation", method)
            }
            callback(method, impl)
        })
    }
}

declare global {
    var B: (mPtr: NativePointer | number | string | ObjC.Object, filter?:string) => void
    var b: (mPtr: NativePointer | number | string) => void
}

globalThis.b = Breaker.attachMethod
globalThis.B = Breaker.attachClass