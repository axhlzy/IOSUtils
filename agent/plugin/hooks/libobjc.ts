declare global {
    var hook_load_images: () => void
}

export { }

globalThis.hook_load_images = () => {

    // DebugSymbol.fromName("load_images")
    // {
    //     "base": "0x1b14fc000",
    //     "name": "libobjc.A.dylib",
    //     "path": "/usr/lib/libobjc.A.dylib",
    //     "size": 221184
    // }
    Interceptor.attach(DebugSymbol.fromName("load_images").address, {
        onEnter(args) {
            const name = args[0].readCString()
            logd(`Called load_images( ${args[0]} -> ${args[0].readCString()} )`)
            if (name?.includes("UnityFramework")) {
                // showInfo()
                // saveModule("UnityFramework")
                // dumpModule("UnityFramework")
                // dumpAllMd()

                Interceptor.replace(ObjC.classes.WindShareData["- initUserAgent"].implementation, new NativeCallback(() => {
                    logd("nop initUserAgent")
                }, "void", []))

                // UnityFramework!-[BDASignalManager preGetCachedData]
                Interceptor.replace(ObjC.classes.BDASignalManager["- preGetCachedData"].implementation, new NativeCallback(() => {
                    logd("nop BDASignalManager preGetCachedData")
                }, "void", []))

            }
        }
    })

}