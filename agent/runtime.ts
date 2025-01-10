export {}

declare global {
    var libcA: any
}

// usesage : libcA.objc_msgSend / libcA.objc_getClass ...

globalThis.libcA = class libcA {}

if (Process.platform == "darwin") {
    Process.getModuleByName("libobjc.A.dylib").enumerateSymbols().forEach(function(symbol) {
        if (!symbol.name.includes('redacted')) {
            Reflect.set(libcA, symbol.name, symbol.address)
        }
    })
}

// todo : other common libs ...
// ...