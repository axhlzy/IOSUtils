globalThis.hook_dyld_log = () => {
    // dyld::log(char const*, ...)
    // logd(`getSym("dyld::log","dyld") = ${getSym("dyld::log", "dyld")![0].address}`)
    A(getSym("dyld::log", "dyld")![0].address, (args) => {
        logd(`dyld::log ${args[0].readCString()}`)
    })
}

globalThis.hook_dyld_get_image_name = () => {

    logw(`MAIN Process ${Process.id}`)

    // _dyld_image_count
    A(getSym("_dyld_image_count", "dyld")![0].address, undefined, (ret, ctx) => {
        logd(`[ ${Process.getCurrentThreadId()} ] \tcalled _dyld_image_count -> ${ret.toInt32()}`)
        logz(`called from:\n${Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\t\n')}\n`)
    })

    Interceptor.attach(getSym("_dyld_get_image_name", "dyld")![0].address, {
        onEnter(args) {
            this.msg = `_dyld_get_image_name( ${args[0]} | ${args[0].toInt32()} )`
            this.index = args[0].toInt32()
        },
        onLeave(retval) {
            let mm = (`${retval} = ${this.msg}\t<-\t${retval.readCString()}`)
            let mm1 = mm.toLowerCase()
            if (this.index == 0 || mm1.includes("libsubstrate") || mm.includes("CepheiUI") || mm1.includes("substrate")
                || mm1.includes("substitute-loader.dylib") || mm1.includes("libsubstitute.0.dylib") || mm1.includes("libsubstrate.dylib")
                || mm1.includes("FridaAgent") || mm1.includes("FlyJB2.dylib") || mm1.includes("HideJB.dylib")
                || mm1.includes("Cephei") || mm1.includes("CepheiUI") || mm1.includes("zzzzzzzzzNotifyChroot.dylib")
                || mm1.includes("zzzzLiberty.dylib") || mm1.includes("Cephei") || mm1.includes("Cephei")) {
                const newStr = Memory.allocUtf8String(retval.readCString()!.replace("substrate", "sub").replace("stitute", "sub"))
                retval.replace(newStr)
                logw(mm + " | modify to " + retval.readCString())
                logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
            } else {
                logd(mm)
            }
        }
    })
}

// hook __mod_init_funcs
globalThis.hook_dyld_mod_init_funcs = (offset?: NativePointer | number) => {

    // src/ImageLoaderMachO.cpp
    // void ImageLoaderMachO::doModInitFunctions(const LinkContext& context)
    // func(context.argc, context.argv, context.envp, context.apple, &context.programVars);
    function findOffset() {
        const addr = getSym("ImageLoaderMachO::doModInitFunctions", "dyld")![0].address
        let maxInsItor = 200
        let current = Instruction.parse(addr)
        let md = Process.findModuleByName("dyld")!
        const addr_helper = getSym("_ZN4dyld17gLibSystemHelpersE", "dyld")![0].address

        while (--maxInsItor > 0) {
            // logw(`${current.address} ${current.address.sub(md?.base!)} ${current}`)
            if (current.mnemonic == "blr") {
                // loge(`${current.address} ${current.address.sub(md?.base!)} ${current}`)
                // check
                // 0x1042bf2c0 0x172c0 blr x24
                // 0x1042bf2c4 0x172c4 cbnz x22, #0x1042bf2ec
                // 0x1042bf2c8 0x172c8 adrp x8, #0x104314000
                // 0x1042bf2cc 0x172cc add x8, x8, #0x3c8
                const next_1 = Instruction.parse(current.next)
                const next_2 = Instruction.parse(next_1.next)
                const next_3 = Instruction.parse(next_2.next)
                if (next_2.mnemonic == "adrp" && next_3.mnemonic == "add") {
                    const v_2 = Number((next_2 as Arm64Instruction).operands.filter(i => i.type == "imm")[0].value)
                    const v_3 = Number((next_3 as Arm64Instruction).operands.filter(i => i.type == "imm")[0].value)
                    if (addr_helper.equals(v_2 + v_3)) return current.address
                }
            }
            current = Instruction.parse(current.next)
        }
        return NULL
    }

    const nopCall = new NativeCallback(() => {
        logd("nop call 'KSAdSDK!registerDyldCallback'")
    }, "void", [])


    A(offset != undefined ? offset : findOffset(), (_args, ctx) => {
        const x24L = (ctx as Arm64CpuContext).x24
        const debuginfo = DebugSymbol.fromAddress(x24L).toString()
        logd(`call init -> ${x24L} | ${debuginfo}`)

        // {
        //     let ins = Instruction.parse(x24L)
        //     for (let i = 0; i < 500; i++) {
        //         if (i == 0 || i == 499) logw(ins)
        //         if (ins.toString().includes('svc')) loge(`Found SVC ${ins.address} ${ins}`)
        //         ins = Instruction.parse(ins.next)
        //     }
        // }

        // if (debuginfo.includes("KSAdSDK!registerDyldCallback")) {
        //     (ctx as Arm64CpuContext).x24 = nopCall
        // }

        // A(x24L, (args)=>{logz(`Enter ${x24L}`)}, (ret)=>{logz(`Leave ${x24L}`)})

        // if(!debuginfo.includes("UnityFramework")) return
        // Interceptor.attach(x24L, {
        //     onEnter(args) {
        //         logz(`Enter ${x24L}`)
        //         Stalker.follow(Process.getCurrentThreadId(), {
        //             events: {
        //                 call: false,
        //                 // ret: false,
        //                 // exec: true,
        //                 // block: false,
        //                 // compile: false,
        //             },
        //             transform: function (iterator: StalkerArm64Iterator | StalkerArmIterator) {
        //                 let instruction = iterator.next()!
        //                 do {
        //                     let msg = `${DebugSymbol.fromAddress(instruction?.address as NativePointer)} ${instruction}`
        //                     if (instruction.toString().includes("svc")) {
        //                         loge(`${msg}`)
        //                         sleep(3)
        //                     } else {
        //                         logz(`${msg}`)
        //                     }
        //                     iterator.keep()
        //                 } while ((instruction = iterator.next()!) !== null)

        //             }
        //         })
        //     },
        //     onLeave(retval) {
        //         logz(`Leave ${x24L}`)
        //         Stalker.unfollow(Process.getCurrentThreadId())
        //     }
        // })


        // if (debuginfo.includes("UnityFramework") || debuginfo.includes("UnityFramework!0x12") || debuginfo.includes("UnityFramework!0xfc")) {
        // Stalker.follow(Process.getCurrentThreadId(), {
        //     events: {
        //         compile: true
        //     },
        //     onReceive: function (events) {
        //         const bbs = Stalker.parse(events, {
        //             stringify: false,
        //             annotate: false
        //         });
        //         logd("↓ Stalker trace ↓\n")
        //         logd(bbs.flat().map(item => DebugSymbol.fromAddress(ptr(item as unknown as string))).join('\n'));
        //     }
        // })
    })
}

globalThis.hook_dyld_doModInitFunctions = () => {
    // void ImageLoaderMachO::doModInitFunctions(const LinkContext& context)
    A(getSym("doModInitFunctions", "dyld")![0].address, (args) => {
        logd(`Enter doModInitFunctions ImageLoaderMachO:${args[0]} LinkContext&:${args[1]}`)
        // hex(args[1])
    }, () => {
        logd(`Exit doModInitFunctions\n`)
    })
}

globalThis.hook_dyld_ImageLoader_findExportedSymbol = () => {
    // const ImageLoader::Symbol* ImageLoaderMachO::findExportedSymbol(const char* name, bool searchReExports, const char* thisPath, const ImageLoader** foundIn) const
    A(getSym("ImageLoaderMachO::findExportedSymbol", "dyld")![0].address, (args, _ctx, pv) => {
        pv.set('pv', `ImageLoaderMachO::findExportedSymbol( INS:${args[0]}, name=${args[1].readCString()}, searchReExports=${args[2]}, thisPath=${args[3].readCString()}, foundIn=${args[4]} )`)
    }, (retval, _ctx, pv) => {
        logd(`Sym*:${retval} = ${pv.get('pv')}`)
    })
}

globalThis.hook_dyld_ImageLoader_recursiveInitialization = () => {
    // 0x104401ed8 => ImageLoader::recursiveInitialization(ImageLoader::LinkContext const&, unsigned int, char const*, ImageLoader::InitializerTimingList&, ImageLoader::UninitedUpwards&)
    // void recursiveInitialization(const LinkContext& context, mach_port_t this_thread, const char* pathToInitialize, ImageLoader::InitializerTimingList&, ImageLoader::UninitedUpwards&);
    A(getSym("ImageLoader::recursiveInitialization", "dyld")![0].address, (args) => {
        logd(`called ImageLoader::recursiveInitialization( ImageLoader:${args[0]}, context:${args[1]}, this_thread:${args[2].toInt32()}`)
    })
}

globalThis.dyld_register_func = (func: Function) => {

    // struct mach_header {
    //     uint32_t    magic;        /* mach magic number identifier */
    //     int32_t        cputype;    /* cpu specifier */
    //     int32_t        cpusubtype;    /* machine specifier */
    //     uint32_t    filetype;    /* type of file */
    //     uint32_t    ncmds;        /* number of load commands */
    //     uint32_t    sizeofcmds;    /* the size of all the load commands */
    //     uint32_t    flags;        /* flags */
    // };

    // const struct mach_header *header, intptr_t slide
    const addr_dyld_register_func = DebugSymbol.fromName("_dyld_register_func_for_add_image").address
    const func_dyld_register_func = new NativeFunction(addr_dyld_register_func, "pointer", ['pointer'])
    func_dyld_register_func(new NativeCallback(function (header, slide) {
        logd(`_dyld_register_func_for_add_image ${header} ${slide}`)
        func(header, slide)
        return NULL
    }, "pointer", ["pointer", "pointer"]))
}

export { }

declare global {
    var hook_dyld_log: () => void
    var hook_dyld_get_image_name: () => void
    var hook_dyld_mod_init_funcs: () => void
    var hook_dyld_doModInitFunctions: () => void
    var hook_dyld_ImageLoader_findExportedSymbol: () => void
    var hook_dyld_ImageLoader_recursiveInitialization: () => void
    var dyld_register_func: (func: (a1: NativePointer, a2: NativePointer) => void) => void
}