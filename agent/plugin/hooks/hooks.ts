export { }

declare global {
    var hooks: () => void
    var read_plist_file: (file_location: string) => void
    var read_NSUserDefaults: () => void
    var hook_initialize: () => void
    var hook_load: () => void
    var hook_dispatch: () => void
}

globalThis.hooks = () => {

    const ptracePtr = Module.findExportByName(null, "ptrace")
    Interceptor.replace(ptracePtr!, new NativeCallback(function () {
        logd("[*] Ptrace called and replaced")
        return 0
    }, "int", []))

    const sysctlPtr = Module.findExportByName(null, "__sysctl")
    Interceptor.replace(sysctlPtr!, new NativeCallback(function () {
        logd("[*] Sysctl called and replaced")
        return 0
    }, "int", []))

}

// read_plist_file("/path/to/file/filename.plist")
globalThis.read_plist_file = (file_location: string) => {
    const dict = ObjC.classes.NSMutableDictionary
    logd("[*] Read Plist File: " + file_location)
    logd("[*] File Contents:")
    logd(dict.alloc().initWithContentsOfFile_(file_location).toString())
}

//Credit: Objection (https://github.com/sensepost/objection/blob/master/objection/commands/ios/nsuserdefaults.py)
globalThis.read_NSUserDefaults= () => {
    logw("[*] Started: Read NSUserDefaults PLIST file")
    if (ObjC.available) {
        try {
            const NSUserDefaults = ObjC.classes.NSUserDefaults
            const NSDictionary = NSUserDefaults.alloc().init().dictionaryRepresentation()
            logd(NSDictionary.toString())
        } catch (err) {
            logw("[!] Exception: " + err)
        }
    } else {
        logw("Objective-C Runtime is not available!")
    }
    logw("[*] Completed: Read NSUserDefaults PLIST file")
}

globalThis.hook_initialize = ()=>{

    const items = new ApiResolver("objc").enumerateMatches("+[* initialize]")
    logw(`GOT +[* initialize] | size: ${items.length}`)

    items.forEach(v=>{
        Interceptor.attach(v.address, {
            onEnter(args) {
                const debugSym = DebugSymbol.fromAddress(v.address)
                const obj = new ObjC.Object(args[0])
                logd(`called ${v.name} ( ins:${obj}, sel:${ObjC.selectorAsString(args[1])} )`)
                logz(`\t${debugSym.address} -> ${debugSym.moduleName} -> ${DebugSymbol.fromAddress(obj.$class.handle).moduleName}`)
            },
        })
    })

}

globalThis.hook_load = ()=>{

    const items = new ApiResolver("objc").enumerateMatches("+[* load]")
    logw(`GOT +[* load] | size: ${items.length}`)

    items.forEach(v=>{
        Interceptor.attach(v.address, {
            onEnter(args) {
                const debugSym = DebugSymbol.fromAddress(v.address)
                const obj = new ObjC.Object(args[0])
                logd(`called ${v.name} ( ins:${obj}, sel:${ObjC.selectorAsString(args[1])} )`)
                logz(`\t${debugSym.address} -> ${debugSym.moduleName} -> ${DebugSymbol.fromAddress(obj.$class.handle).moduleName}`)
            },
        })
    })

}

globalThis.hook_dispatch = ()=>{
    logw(`TODO`)
}