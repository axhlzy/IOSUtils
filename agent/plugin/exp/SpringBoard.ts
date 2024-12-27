// /Users/lzy/Library/Developer/Xcode/iOS DeviceSupport/iPhone10,4 14.3 (18C66)/Symbols/System/Library/PrivateFrameworks/SplashBoard.framework/SplashBoard
const test_sb = ()=> {

    // -[XBLaunchStateRequest urlSchemeName]
    Interceptor.attach(ObjC.classes["XBLaunchStateRequest"]["- urlSchemeName"].implementation, {
        onEnter(args) {
            logd(`\nCalled XBLaunchStateRequest ${new ObjC.Object(args[0])}`)
        },
        onLeave(retval) {
            logd(`Returned ${new ObjC.Object(retval)}`)
        }
    })

    // frida-trace -U -p 12211 -m "*[XBApplication* *]"
    // -[XBApplicationLaunchCompatibilityInfo bundlePath]
    Interceptor.attach(ObjC.classes["XBApplicationLaunchCompatibilityInfo"]["- bundlePath"].implementation, {
        onEnter(args) {
            logd(`\nCalled XBApplicationLaunchCompatibilityInfo ${new ObjC.Object(args[0])}`)
        },
        onLeave(retval) {
            logd(`Returned ${new ObjC.Object(retval)}`)
        }
    })

}