export { }

// 放假放假 代码刚写完 还没来得及测试 
class Breaker {

    // ref function ptr => IMP
    public static attachImpl(mPtr: NativePointer | number | string, defaultArgsC: number = 4) {
        const localPtr: NativePointer = checkPointer(mPtr)
        Interceptor.attach(localPtr, {
            onEnter(args) {
                let args_str = Array.from({ length: defaultArgsC }, (_, i) => args[i].toString()).join(', ')
                logd(`called ${localPtr} | args -> ${args_str}`)
            }
        })
    }

    //  ref Method => Method
    public static attachMethod(mPtr: NativePointer | number | string | ObjC.ObjectMethod) {
        const localPtr: NativePointer = checkPointer(mPtr)
        var method = new ObjC.Class(localPtr) as unknown as ObjC.ObjectMethod // ref ObjectMethod
        var old_impl = method.implementation as any
        const count: number = call("method_getNumberOfArguments", method).toInt32()
        method.implementation = ObjC.implement(method, function (clazz: NativePointer, selector: any, ...args: any[]) {
            logw(`called ${ObjC.selectorAsString(selector)}`)
            for (let i = 0; i < count - 2; i++) {
                logz(`\t Arg ${i + 1}: ${args[i]}`)
            }
            return old_impl(clazz, selector, ...args)
        })
    }

    // ref Class / ObjC.Object
    public static attachClass(mPtr: NativePointer | number | string | ObjC.Object) {
        const localPtr: NativePointer = checkPointer(mPtr)
        const localObj = new ObjC.Class(localPtr) // ref Class
        Breaker.itorMethod(localObj, (method, _impl) => Breaker.attachMethod(method))
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
    var B: (mPtr: NativePointer | number | string | ObjC.Object) => void
    var b: (mPtr: NativePointer | number | string | ObjC.ObjectMethod) => void
}

globalThis.b = Breaker.attachMethod
globalThis.B = Breaker.attachClass