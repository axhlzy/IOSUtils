export {}

// NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier];
const get_BundleIdentifier = ()=>{
    return ObjC.classes["NSBundle"]["mainBundle"]()["bundleIdentifier"]().toString()
}

declare global {
    var get_BundleIdentifier:()=>string
}

globalThis.get_BundleIdentifier = get_BundleIdentifier