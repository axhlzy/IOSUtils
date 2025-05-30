import { HK_TYPE } from "../../utils.js"
import { argType, getArgsAndRet, packArgs, parseType } from "../lang/oc/oc.js"

export { }

const default_hook_type = HK_TYPE.OBJC_REP

class Breaker {
    // ref function ptr => IMP
    public static attachImpl(mPtr: NativePointer, hookType: HK_TYPE = default_hook_type) {
        objc_method.fromAddress(mPtr).hook(hookType)
    }

    //  ref Method => Method
    public static attachMethod(method: ObjectWrapper, bt: boolean = false, hookType: HK_TYPE = default_hook_type) {
        objc_method.fromMethod(method).hook(hookType, false, bt)
    }

    // -[Viber.AddFriendViewControllerInjectionImpl addressBook]
    public static attachMethodString(hkStr: string, hookType: HK_TYPE = default_hook_type) {
        objc_method.fromString(hkStr).hook(hookType)
    }

    // ref Class / ObjC.Object
    public static attachClass(mPtr: NativePointer | number | string | ObjC.Object, filterMethodNameStr: string = '', force: boolean = false) {
        if (typeof mPtr == "string" && mPtr.startsWith("0x")) mPtr = ptr(mPtr)
        const localPtr: NativePointer = checkPointer(mPtr)
        const localObj = new ObjC.Class(localPtr) // ref Class
        Breaker.itorMethod(localObj, (method: ObjC.ObjectMethod, _impl) => {
            const methodName = `${ObjC.selectorAsString(method.selector)}`
            if (methodName.includes(filterMethodNameStr)) Breaker.attachMethod(method)
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
                    // impl = Hook_Status.getNewImplFromOCMethod(objc_method.fromMethod(method))!
                    throw error
                }
            } catch (error) {
                const selector = call("NSSelectorFromString", allocOCString(m.substring(m.indexOf(' ') + 1)))
                const method_ptr = ObjC.api.class_getInstanceMethod(obj, selector)
                method = new ObjC.Object(method_ptr) as any
                impl = call("method_getImplementation", method)
            }
            callback(method, impl)
        })
    }

    public static attachMethodsByFilter(filterName: string, filterClass: string = '', type: ApiResolverType = "objc") {
        if (filterName == undefined || filterName.length == 0) throw new Error('Need args[0] filterStr: string')
        let filter: string = filterName
        if (filterClass != undefined && filterClass != '' && !filterName.includes("[")) {
            filter = `*[${filterClass} *${filterName}*]`
        } else if (!filterName.includes("[")) {
            filter = `*[* *${filterName}*]`
        }
        new ApiResolver(type).enumerateMatches(filter).forEach((item, index) => {
            try {
                // debug info
                // logd(`[${index}] \taddr:${item.address} offset:${md?.name}@${item.address.sub(md?.base!)} ${item.name} ObjM:${method.handle}`)
                Breaker.attachImpl(item.address)
            } catch (error) {
                loge(`${item.address} ${error}`)
            }
        })
    }
}

declare global {
    // 针对类方法简单解析
    var B: (mPtr: NativePointer | number | string | ObjC.Object, filter?: string) => void
    // 针对方法名过滤批量hook
    var BF: (fMethodName: string, filterClass?: string, type?: ApiResolverType) => void
    // 针对单个方法
    var b: (mPtr: NativePointer | number | string) => void

    // hook 一个地址
    var ba: (mPtr: NativePointer | number | string) => void
}

globalThis.b = (mPtr: NativePointer | number | string, bt: boolean = false) => {
    if (typeof mPtr == 'number') mPtr = ptr(mPtr)
    if (typeof mPtr == 'string') {
        if (mPtr.startsWith("0x")) mPtr = ptr(mPtr)
        else return Breaker.attachMethod(nameToMethod(mPtr), bt)
    }
    Breaker.attachMethod(new ObjC.Object(mPtr), bt)
}

globalThis.B = Breaker.attachClass
globalThis.BF = Breaker.attachMethodsByFilter

globalThis.ba = (mPtr: NativePointer | number | string, argC: number = 4, bt: boolean = false) => {
    mPtr = checkPointer(mPtr)
    Interceptor.attach(mPtr, {
        onEnter: function (args) {
            let argsStr: string[] = []
            for (let i = 0; i < argC; i++) argsStr.push(args[i].toString())
            this.msg = (`Called -> ${mPtr} [ ${argsStr.join(', ')} ]`)
        },
        onLeave: function (retval) {
            logd(`${this.msg} => ${retval}`)
            if (bt) logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
        }
    })
}