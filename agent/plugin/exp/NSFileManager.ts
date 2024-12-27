export const hook_NSFileManager = () => {

    Interceptor.attach(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const nsstring = new ObjC.Object(args[3])
            console.warn(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
        }
    })

    Interceptor.replace(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, new NativeCallback(function (arg0, arg1, arg2) {
        const ins = new ObjC.Object(arg0)
        const sel = ObjC.selectorAsString(arg1)
        const nsstring = new ObjC.Object(arg2)
        logw(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
    }, "void", ["pointer", "pointer", "pointer"]))

}