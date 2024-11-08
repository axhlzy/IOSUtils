globalThis.hook_dlopen = (onCall?:(name:string)=>void, printBackTrace:boolean=false) => {
    // void* dlopen(const char* filename, int flag);
    A(DebugSymbol.fromName("dlopen").address, (args,ctx,pv)=>{
        if (args[0].isNull()) return
            const name = args[0].readCString()
            pv.set("msg", `dlopen ( ${args[0]} ${name}, ${args[1]} )`)
            if (printBackTrace) logw('dlopen called from:\n' + Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n')
        },(retval, _ctx, pv)=>{
            logd(`${retval} = ${pv.get("msg")}`)
        }
    )
}

export { }

declare global {
    var hook_dlopen: () => void
}