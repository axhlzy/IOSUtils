export const hook_NSProcessInfo = () => {

    // +[NSProcessInfo processInfo]
    Interceptor.attach(ObjC.classes["NSProcessInfo"]["+ processInfo"].implementation, {
        onLeave(retval) {
            let env = new ObjC.Object(retval)["- environment"]()
            let env_mut = new ObjC.Object(env)["- mutableCopy"]()
            logd(`called NSProcessInfo.processInfo ${retval} | env:${env_mut}`)
            env_mut["- removeObjectForKey:"]("DYLD_INSERT_LIBRARIES")
            env_mut["- setObject:forKey:"]("DYLD_INSERT_LIBRARIES", "/usr/lib/substitute-loader.dylib")

        }
    })

    ObjC.classes["NSProcessInfo"]["+ processInfo"]


    // -[NSProcessInfo environment]
    Interceptor.attach(ObjC.classes["NSProcessInfo"]["- environment"].implementation, {
        onLeave(retval) {
            var env_mut = new ObjC.Object(retval)["- mutableCopy"]()
            logd(`called NSProcessInfo.processInfo ${retval} | env:${env_mut}`)
            printBacktrace(this.context)
            env_mut["- removeObjectForKey:"]("DYLD_INSERT_LIBRARIES")
            // env_mut["- setObject:forKey:"]("/usr/lib/substitute-loader.dylib", "DYLD_INSERT_LIBRARIES")
            retval.replace(env_mut)
            printDictionary(retval)
        }
    })

    // LOGJSON(Process.findModuleByAddress(DebugSymbol.fromName("getenv").address))

    // Key: __CF_USER_TEXT_ENCODING, Value: 0x1F5:0:0
    // Key: TMPDIR, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F/tmp/
    // Key: XPC_FLAGS, Value: 0x0
    // Key: SHELL, Value: /bin/sh
    // Key: HOME, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F
    // Key: XPC_SERVICE_NAME, Value: UIKitApplication:com.kldlz.ios.sqhd[a1a2][rb-legacy]
    // Key: PATH, Value: /usr/bin:/bin:/usr/sbin:/sbin
    // Key: CLASSIC_OVERRIDE, Value: 0
    // Key: LOGNAME, Value: mobile
    // Key: USER, Value: mobile
    // Key: CFFIXED_USER_HOME, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F


    // Key: PATH, Value: /usr/bin:/bin:/usr/sbin:/sbin
    // Key: TMPDIR, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F/tmp/
    // Key: LOGNAME, Value: mobile
    // Key: XPC_FLAGS, Value: 0x0
    // Key: HOME, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F
    // Key: CFFIXED_USER_HOME, Value: /private/var/mobile/Containers/Data/Application/DEB6BEC0-1A22-493D-95D2-A09FF71B8F7F
    // Key: USER, Value: mobile
    // Key: CLASSIC_OVERRIDE, Value: 0
    // Key: XPC_SERVICE_NAME, Value: UIKitApplication:com.kldlz.ios.sqhd[0d5f][rb-legacy]
    // Key: SHELL, Value: /bin/sh
    // Key: __CF_USER_TEXT_ENCODING, Value: 0x1F5:0:0
    // Key: DYLD_INSERT_LIBRARIES, Value: /usr/lib/substitute-loader.dylib
}