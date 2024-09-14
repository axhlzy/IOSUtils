export {}

const B_NSLOG = () => {
    const address = Module.findExportByName("Foundation", "NSLog")
    if (!address) return loge("NSLog address not found!")

    Interceptor.attach(address!, {
        onEnter(args) {
            const fmt = new ObjC.Object(args[0]).toString() // NSString
            const count_args = fmt.split("%").length - 1   
            let args_str = ''
            for (let i = 1; i < count_args+1; i++) {
                args_str += args[i].toString() 
                args_str += ', '
            }
            logd(`NSLog: ${fmt} | ${args_str}`)
        }
    })
}

declare global {
    var B_NSLOG : () => void
}

globalThis.B_NSLOG = B_NSLOG