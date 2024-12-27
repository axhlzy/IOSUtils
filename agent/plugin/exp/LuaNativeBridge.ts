
const test_LuaNativeBridge = () => {
    // +[LuaNativeBridge callOC:withMethod:withJSONString:]
    Interceptor.attach(ObjC.classes["LuaNativeBridge"]["+ callOC:withMethod:withJSONString:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const json = new ObjC.Object(args[2]).toString()
            logw(`\nCalled LuaNativeBridge ${ins} ${sel} ${json}`)
            printBacktrace(this.context)
        }
    })
}