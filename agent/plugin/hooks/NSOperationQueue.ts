declare global {
    var hook_NSOperationQueue: () => void
}

export { }

globalThis.hook_NSOperationQueue = () => {

    // ------------------------------------------------------------
    // Name                    ->      addOperationWithBlock:
    // NumberOfArguments       ->      3
    // TypeEncoding            ->      v24@0:8@?16
    // ObjectMethod            ->      0x1f2029400
    // Implementation          ->      0x1b1289c0c | 0x54c0c
    // ReturnType
    //         ret:            v - void
    // ArgumentTypes
    //         args[0]:        @ - object
    //         args[1]:        : - selector
    //         args[2]:        @? - block

    // [NSOperationQueue addOperationWithBlock:]
    Interceptor.attach(ObjC.classes["NSOperationQueue"]["- addOperationWithBlock:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const blk = new ObjC.Block(args[2])
            console.warn(`-[NSOperationQueue addOperationWithBlock] ${ins} ${sel} ${blk} @ ${args[2]}`)
            logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
        }
    })

    // [NSOperationQueue addOperation:]
    Interceptor.attach(ObjC.classes["NSOperationQueue"]["- addOperation:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const blk = new ObjC.Block(args[2])
            console.warn(`-[NSOperationQueue addOperation] ${ins} ${sel} ${blk} @ ${args[2]}`)
            logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
        }
    })

    // ------------------------------------------------------------
    // Name                    ->      mainQueue
    // NumberOfArguments       ->      2
    // TypeEncoding            ->      @16@0:8
    // ObjectMethod            ->      0x1f202a2c8
    // Implementation          ->      0x1b1244e10 | 0xfe10
    // ReturnType
    //         ret:            @ - object
    // ArgumentTypes
    //         args[0]:        @ - object
    //         args[1]:        : - selector

    // [NSOperationQueue mainQueue]
    Interceptor.attach(ObjC.classes["NSOperationQueue"]["+ mainQueue"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            this.msg = `-[NSOperationQueue mainQueue] ${ins} ${sel}`
        },
        onLeave(retval) {
            let msgL = this.msg
            logd(`${new ObjC.Object(retval)} = ${msgL}`)
            logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
        },
    })
}