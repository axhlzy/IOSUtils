const hook_NSAlertController_messageText = () => {

    // -[NSAlertController messageText]
    Interceptor.attach(ObjC.classes["NSAlertController"]["- messageText"].implementation, {
        onEnter(args) {
        },
        onLeave(retval) {
            logd(new ObjC.Object(retval))
        },
    })

    // -[UIAlertController message]
    Interceptor.attach(ObjC.classes["UIAlertController"]["- message"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            logw(`\nCalled UIAlertController ${ins}`)
        },
        onLeave(retval) {
            logw(`\nUIAlertController message => ${new ObjC.Object(retval)}`)
        }
    })

}
