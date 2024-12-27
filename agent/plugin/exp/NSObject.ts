export const NSObject_onThread = () => {
    // -[NSObject(NSThreadPerformAdditions) performSelector:onThread:withObject:waitUntilDone:modes:]
    Interceptor.attach(ObjC.classes["NSObject"]["- performSelector:onThread:withObject:waitUntilDone:modes:"].implementation, {
        onEnter(args) {
            logw(`\nCalled NSObject performSelector:${ObjC.selectorAsString(args[2])} onThread:${new ObjC.Object(args[3])} withObject:${new ObjC.Object(args[4])} waitUntilDone:${args[5]} modes:${args[6]}`)
            printBacktrace(this.context)
        }
    })
}