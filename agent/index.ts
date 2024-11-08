import './include.js'
import './logger.js'

// hook_exit()
// hook_strcmp()
// hook_all_detect()

// A(Module.getExportByName(null, "_pthread_start"),(args, ctx)=>{
//     logd("called _pthread_start")
//     let logs = `called from:\n${Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`
//     log(logs)
// })
// A(Module.getExportByName(null, "pthread_create"),(args, ctx)=>{
//     logd("called pthread_create")
//     let logs = `called from:\n${Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`
//     log(logs)
// })

hook_dyld_get_image_name()

hook_dyld_mod_init_funcs()

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

// B("UPWDeviceUtil")

// -m "*[* *canOpenURL*]"