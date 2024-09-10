export {}

const hook_thread = ()=>{

    // libsystem_pthread.dylib!_pthread_start
    Interceptor.attach(Module.getExportByName("libsystem_pthread.dylib", "_pthread_start"),{
        onEnter: function(args){
            const backTrace = 'called from:\n' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n'
            console.log(backTrace)
            if (backTrace.includes("tersafe2")) {
                loge("[!] _pthread_start called")
            } else {
                logd("[!] _pthread_start called")
            }
            console.log("[*] _pthread_start called")
            console.log("[*] args[0]",args[0])
            console.log("[*] args[1]",args[1])
            console.log("[*] args[2]",args[2])
        }
    })

}

declare global {
    var hook_thread: any;
}

globalThis.hook_thread = hook_thread