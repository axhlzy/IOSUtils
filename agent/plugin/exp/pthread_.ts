export const hook_pthread_ = () => {

    // pthread_create(thread=0x283bada28, attr=0x283bad9e8, start_routine=0x184a3316c, arg=0x281fcbf00)
    A(Module.getExportByName(null, "pthread_create"), (args, ctx) => {
        logd(`called pthread_create ${DebugSymbol.fromAddress(args[2])}`)
        let logs = `called from:\n${Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`
        log(logs)
    })

    // pthread_exit
    Interceptor.attach(Module.findExportByName(null, "pthread_exit")!, {
        onEnter(args) {
            const exitCode = args[0]
            logw(`\n[${Process.getCurrentThreadId()}] Called pthread_exit \n\texitCode:${exitCode}`)
        }
    })

}