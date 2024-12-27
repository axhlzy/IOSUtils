const test_getenv = () => {
    Interceptor.attach(Module.findExportByName(null, "getenv")!, {
        onEnter(args) {
            const s = args[0].readCString()
            this.msg = s
            if (s == "DYLD_INSERT_LIBRARIES") {
                this.md = true
            }
        },
        onLeave(retval) {
            if (this.md) {
                loge(`<= DYLD_INSERT_LIBRARIES ${retval}`)
                printBacktrace(this.context)
                retval.replace(NULL)
            }
            logd(`called getenv ( ${this.msg} => ${retval} | ${retval.isNull() ? "" : retval.readCString()})`)
        },
    })
}