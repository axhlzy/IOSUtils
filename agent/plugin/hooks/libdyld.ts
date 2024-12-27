globalThis.hook_dlopen = (onCall?:(name:string)=>void, printBackTrace:boolean=false) => {
    // void* dlopen(const char* filename, int flag);
    A(DebugSymbol.fromName("dlopen").address, (args,ctx,pv)=>{
        if (args[0].isNull()) return
            const name = args[0].readCString()
            pv.set("msg", `dlopen ( ${args[0]} ${name}, ${args[1]} )`)
            if (printBackTrace) logw('dlopen called from:\n' + Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n')
        },(retval, _ctx, pv)=>{
            const msg = `${pv.get("msg")}`
            logd(`${retval} = ${msg}`)
            if (msg.includes("CFNetwork")){
                // Interceptor.replace(Process.findModuleByName("TuanjieFramework")!.base.add(0x4AD380), new NativeCallback((arg) => {
                //     logw(`\n[${Process.getCurrentThreadId()}] Called TuanjieFramework!0x4AD380 \n\targs:${arg}`)
                //     return ptr(0)
                // }, "pointer", ["pointer"]))

                // 3A3F20
                // let addr = Process.findModuleByName("TuanjieFramework")!.base.add(0x3A2274)
                // // new Arm64Writer(addr).putRet()

                // // sub_3A2274
                // Interceptor.replace(addr, new NativeCallback((arg) => {
                //     logw(`\n[${Process.getCurrentThreadId()}] Called TuanjieFramework!0x3A2274 \n\targs:${arg}`)
                //     return ptr(0)
                // }, "pointer", ["pointer"]))
            }
        }
    )
}

export { }

declare global {
    var hook_dlopen: () => void
}