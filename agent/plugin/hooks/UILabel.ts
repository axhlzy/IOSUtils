declare global {
    var hook_UILabel: () => void
}

export { }

globalThis.hook_UILabel = () => {

    // -[UILabel setText:]
    Interceptor.attach(ObjC.classes["UILabel"]["- setText:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const nsstring = new ObjC.Object(args[2])
            console.warn(`-[UILabel setText] ${ins} ${sel} '${nsstring}'`)
            logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
        }
    })
    
}