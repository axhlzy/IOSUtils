const test_UITextField = ()=> {

    // -[UITextField textInputView]
    Module.load("/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore")
    Interceptor.attach(ObjC.classes["UITextField"]["- textInputView"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            logd(`\nCalled UITextField ${ins} ${sel} ${ins["- textInputTraits"]()}`)

            // - placeholder
            logw(`placeholder -> ${ins["- placeholder"]()}`)
            if (ins["- placeholder"]() == "密码") {
                ins["- textInputTraits"]()["- setKeyboardType:"](0)
                // secureTextEntry
                ins["- textInputTraits"]()["- setSecureTextEntry:"](false)
            }
        }
    })

    // noCopyTextField - canPerformAction:withSender:
    Interceptor.attach(ObjC.classes["UITextField"]["- canPerformAction:withSender:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            loge(`\nCalled UITextField ${ins} ${sel} ${asOcSELtoString(args[2])} ${new ObjC.Object(args[3])}`)
        },
        onLeave(retval) {
            logd(`Returned ${retval}`)
        }
    })

    Interceptor.replace(ObjC.classes["UITextField"]["- canPerformAction:withSender:"].implementation, new NativeCallback
        (function (self, sel, action, sender) {
            logd(`\nCalled UITextField ${self} ${sel} ${action} ${sender}`)
            return ptr(0)
        }, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']))

}
