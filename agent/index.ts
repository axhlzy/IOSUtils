import './include.js'
import './logger.js'
import { hook_NSProcessInfo } from './plugin/exp/NSProcessInfo.js'
import { hook_pthread_ } from './plugin/exp/pthread_.js'
import { SIGNAL } from './plugin/memory/findsvc.js'

logd(Process.getCurrentThreadId())

// hook_strcmp()
// hook_all_detect()

// hook_dyld_get_image_name()
// hook_dyld_mod_init_funcs()
// hook_dyld_doModInitFunctions()

// hook_dlopen()
// hook_load_images()
// hook_getenv()
// hook_initialize()
// hook_load()
// hook_dispatch()
// hook_NSProcessInfo()
// hook_pthread_()


// examples ↓ 

// OC replace
// const oc_src: ObjC.ObjectMethod = ObjC.classes["BCEUIAlertAction"]["- alertUserInMainThreadWithType:withMessage:withTitle:"]
// const newM = ObjC.implement(oc_src, (ins_, sel_, v, v1) => {
//     const ins = new ObjC.Object(ins_)
//     const sel = ObjC.selectorAsString(sel_)
//     console.warn(`-[BCEUIAlertAction alertUserInMainThreadWithType] ${ins} ${sel} `)
// })
// oc_src.implementation = newM


// // -[ISLanguageSetupController setLanguage:0x8dcc5b6d84ef5a86 specifier:0x0]
// Interceptor.attach(ObjC.classes["ISLanguageSetupController"]["- setLanguage:specifier:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const value = new ObjC.Object(args[2])
//         logw(`\nCalled ISLanguageSetupController \n\t${ins} \n\t${sel} \n\tsetLanguage:'${value}'`)
//     }
// })