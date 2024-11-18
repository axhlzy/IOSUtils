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

// hook_dyld_get_image_name()

// hook_dyld_mod_init_funcs()

// nopSysCall()
// findBRKInstructions()

// ObjC.classes.NSMutableDictionary.dictionary()

// -[BCERoot getJailbreakInfos]
// Interceptor.attach(ObjC.classes["BCERoot"]["- getJailbreakInfos"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         console.warn(`-[BCERoot getJailbreakInfos] ${ins} ${sel}`)
//     },
//     onLeave(retval) {
//         console.warn(`-[BCERoot getJailbreakInfos] ${retval}`)
//         printDictionary(retval)
//         const NSMutableDictionary = ObjC.classes.NSMutableDictionary
//         const emptyDict = NSMutableDictionary.alloc().init()
//         retval.replace(emptyDict)
//     }
// })

// // +[NBSSingletonHelper disbleJailbreakDataCollection]
// Interceptor.attach(ObjC.classes["NBSSingletonHelper"]["+ disbleJailbreakDataCollection"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         console.warn(`-[NBSSingletonHelper disbleJailbreakDataCollection] ${ins} ${sel}`)
//         logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
//     },
//     onLeave(retval) {
//         logz(`disbleJailbreakDataCollection => ${retval}`)
//         retval.replace(ptr(1))
//     }
// })

// sub_10000C8E4
// if (ObjC.available){
//     Interceptor.attach(Process.mainModule.base.add(0xC8E4), {
//         onEnter(args) {
//             logz(`called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`)
//         },
//     })



    // ObjC.classes.BCERoot.sharedInstance().getJailbreakInfos()

    // // [[NSProcessInfo processInfo] environment]
    // ObjC.classes.NSProcessInfo.processInfo().environment()

// }


// // 需要确保 Frida 附加到目标进程后才能运行此代码
// if (ObjC.available) {
//     // 获取 NSMutableDictionary 类
//     const NSMutableDictionary = ObjC.classes.NSMutableDictionary;

//     // 示例拦截一个方法返回的 NSMutableDictionary 并打印其内容
//     Interceptor.attach(NSMutableDictionary["- someMethodReturningDictionary"].implementation, {
//         onLeave: function(retval) {
//             // 将返回值转换为 Objective-C 对象
//             const dictionary = new ObjC.Object(retval);

//             // 检查是否为 NSMutableDictionary 实例
//             if (dictionary.isKindOfClass_(NSMutableDictionary)) {
//                 console.log("Printing NSMutableDictionary contents:");
//                 printDictionary(dictionary);
//             }
//         }
//     });
// } else {
//     console.log("Objective-C runtime is not available!");
// }


// const oc_src: ObjC.ObjectMethod = ObjC.classes["BCEUIAlertAction"]["- alertUserInMainThreadWithType:withMessage:withTitle:"]
// const newM = ObjC.implement(oc_src, (ins_, sel_, v, v1) => {
//     const ins = new ObjC.Object(ins_)
//     const sel = ObjC.selectorAsString(sel_)
//     console.warn(`-[BCEUIAlertAction alertUserInMainThreadWithType] ${ins} ${sel} `)
// })
// oc_src.implementation = newM


// -[NSFileManager fileExistsAtPath:0x107376360]

// Interceptor.attach(ObjC.classes["NSFileManager"]["- fileExistsAtPath:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const nsstring = new ObjC.Object(args[3])
//         console.warn(`\nCalled NSFileManager ${ins} ${sel} fileExistsAtPath:'${nsstring}'`)
//     }
// })

// frida-trace -U -f  com.cmbc.mobilePhone -m "*[NSFileManager *]" -i _dyld_get_image_name -i abort   

// B("UPWDeviceUtil")

// -m "*[* *canOpenURL*]"