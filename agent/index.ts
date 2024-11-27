import './include.js'
import './logger.js'

// hook_exit()
// hook_strcmp()
// hook_all_detect()

// hook_dyld_get_image_name()
// hook_dyld_mod_init_funcs()

// hook_dlopen()
// hook_load_images()
// hook_getenv()
// hook_initialize()
// hook_load()
// hook_dispatch()

// B("UPWDeviceUtil")
// -m "*[* *canOpenURL*]"

// nopSysCall()
// findBRKInstructions()

// ObjC.classes.NSMutableDictionary.dictionary()

// OC replace
// const oc_src: ObjC.ObjectMethod = ObjC.classes["BCEUIAlertAction"]["- alertUserInMainThreadWithType:withMessage:withTitle:"]
// const newM = ObjC.implement(oc_src, (ins_, sel_, v, v1) => {
//     const ins = new ObjC.Object(ins_)
//     const sel = ObjC.selectorAsString(sel_)
//     console.warn(`-[BCEUIAlertAction alertUserInMainThreadWithType] ${ins} ${sel} `)
// })
// oc_src.implementation = newM

// Interceptor.attach(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const nsstring = new ObjC.Object(args[3])
//         console.warn(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
//     }
// })

// Interceptor.replace(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, new NativeCallback(function(arg0,arg1,arg2){
//     const ins = new ObjC.Object(arg0)
//     const sel = ObjC.selectorAsString(arg1)
//     const nsstring = new ObjC.Object(arg2)
//     logw(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
// }, "void", ["pointer", "pointer", "pointer"]))

// frida-trace -U -f  com.cmbc.mobilePhone -m "*[NSFileManager *]" -i _dyld_get_image_name -i abort   

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