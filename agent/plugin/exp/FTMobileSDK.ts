const test_FTMobileSDK = () => {
    // FTMobileSDK!-[FTUncaughtExceptionHandler handleException:]
    Interceptor.attach(ObjC.classes["FTUncaughtExceptionHandler"]["- handleException:"].implementation, {
        onEnter(args) {
            const exception = new ObjC.Object(args[2])
            logw(`\nCalled FTMobileSDK!-[FTUncaughtExceptionHandler handleException:] \n\t${exception}`)

        }
    })
}