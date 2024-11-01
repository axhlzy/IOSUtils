import './include.js'
import './logger.js'

// hook_exit()
// hook_strcmp()
// hook_all_detect()

// -[NSFileManager fileExistsAtPath:0x107376360]

// Interceptor.attach(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const nsstring = new ObjC.Object(args[3])
//         console.warn(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
//     }
// })

// frida-trace -U -f  com.sysh.shajzmjl -m "*[NSFileManager *]" -i _dyld_get_image_name -i abort   

// // __mod_init_func

// // dlsym
// DebugSymbol.fromName("__mod_init_func")

// const addr_dlsym = DebugSymbol.fromName("dlsym").address
// const func_dlsym = new NativeFunction(addr_dlsym, 'pointer', ['pointer', 'pointer'])

// const addr_sleep = DebugSymbol.fromName("sleep").address
// const func_sleep = new NativeFunction(addr_sleep, 'pointer', ['int'])

// // let md = Process.findModuleByName("Unity-iPhone5")



// // struct mach_header {
// //     uint32_t    magic;        /* mach magic number identifier */
// //     int32_t        cputype;    /* cpu specifier */
// //     int32_t        cpusubtype;    /* machine specifier */
// //     uint32_t    filetype;    /* type of file */
// //     uint32_t    ncmds;        /* number of load commands */
// //     uint32_t    sizeofcmds;    /* the size of all the load commands */
// //     uint32_t    flags;        /* flags */
// // };

// // const struct mach_header *header, intptr_t slide
// // let sym_dyld_register_func = DebugSymbol.fromName("_dyld_register_func_for_add_image")
// // let addr_dyld_register_func = sym_dyld_register_func.address
// // let func = new NativeFunction(addr_dyld_register_func, "pointer", ['pointer'])
// // func(new NativeCallback(function (header, slide) {
// //     logd(`_dyld_register_func_for_add_image ${header} ${slide}`)
// //     return NULL
// // }, "pointer", ["pointer", "pointer"]))

// let base: NativePointer
// Interceptor.attach(DebugSymbol.fromName("dlopen").address, {
//     onEnter(args) {
//         if (args[0].isNull()) return
//         const name = args[0].readCString()
//         if ((name as string).includes("Unity-iPhone5")) {
//             loge(`dlopen ${args[0]} ${name}`)

//             dowk()


//         } else {
//             logd(`dlopen ${args[0]} ${name}`)
            
//             logw('dlopen called from:\n' +
//                 Thread.backtrace(this.context, Backtracer.ACCURATE)
//                     .map(DebugSymbol.fromAddress).join('\n') + '\n')
//         }
//         this.n = name
//     },
//     onLeave(retval) {
//         // logd(`| dlopen ${this.n}`)
//     },
// })

// function dowk() {
//     let md = Process.findModuleByName("Unity-iPhone5")
//     logw(JSON.stringify(md))
//     // md?.enumerateSymbols().forEach(item => {
//     //     logd(JSON.stringify(item))
//     // })

//     if (base == undefined) {
//         base = md?.base!
//         let addr = base.add(0x1333C90)
//         console.warn(hexdump(addr!))

//         var target = addr!
//         var index = 0
//         while (target.readPointer() != NULL && !target.readPointer().isNull()) {

//             const target_cp = target
//             const targetAddr = target.readPointer()
//             const index_ = target.sub(addr).toInt32() / Process.pointerSize
//             logd(`Attach -> ${index} ${targetAddr}`)

//             const srcCall = new NativeFunction(targetAddr, "void", [])
//             Interceptor.replace(targetAddr, new NativeCallback(function(){
//                 logw(`Before\t__mod_init_func_${index_} ${targetAddr} ${target_cp.sub(base)}`)
//                 // console.warn(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"))
//                 if (index_ != 3)
//                     srcCall()
//                 logw(`After\t__mod_init_func_${index_} ${targetAddr} ${target_cp.sub(base)}`)
//                 func_sleep(0.5)
//             }, "void", []))

//             // Interceptor.attach(targetAddr, {
//             //     onEnter(args) {
//             //         logw(`onEnter __mod_init_func_${index_} ${targetAddr} ${target.sub(base)}`)
//             //         console.warn(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"))
//             //     },
//             //     onLeave(retval) {
//             //         logw(`onLeave __mod_init_func_${index_} ${targetAddr} ${target.sub(base)}`)
//             //     }
//             // })

//             ++index
//             target = target.add(Process.pointerSize)
//         }

//         // func_sleep(10)
//     }
// }

// B("UPWDeviceUtil")