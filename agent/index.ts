import './include.js'
import './logger.js'
import { hook_NSProcessInfo } from './plugin/exp/NSProcessInfo.js'
import { hook_pthread_ } from './plugin/exp/pthread_.js'
import { SIGNAL } from './plugin/memory/findsvc.js'

logd(`PID:\t${Process.id}`)
logd(`TID:\t${Process.getCurrentThreadId()}`)

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

// showInfo()

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

// // -[FBProcessExecutionContext setWatchdogProvider:0x2828c1760]
// Interceptor.attach(ObjC.classes["FBProcessExecutionContext"]["- setWatchdogProvider:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const value = new ObjC.Object(args[2])
//         logw(`\nCalled FBProcessExecutionContext \n\t${ins} \n\t${sel} \n'${value}'`)
//         // args[2] = NULL
//         // [[[SBSceneWatchdogProvider alloc] init] initAsDisabled:true]
//         const newWdog = ObjC.classes["SBSceneWatchdogProvider"].alloc().init().initAsDisabled_(true)
//         args[2] = newWdog.handle
//     }
// }) 

// //  -[FBProcessExecutionContext setWaitForDebugger:0x0]
// Interceptor.attach(ObjC.classes["FBProcessExecutionContext"]["- setWaitForDebugger:"].implementation, {
//     onEnter: function (args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         const value = args[2]
//         logw(`\nCalled setWaitForDebugger: \n\t${ins} \n\t${sel} \n'${value}'`)
//         args[2] = ptr(1)
//     }
// })

// // -[LSApplicationProxy _initWithContext:0x16f41e6a0 bundleUnit:0x130 applicationRecord:0x281952580 bundleID:0x1ea2e1130 resolveAndDetach:0x1]
// Interceptor.attach(ObjC.classes.LSApplicationProxy["- _initWithContext:bundleUnit:applicationRecord:bundleID:resolveAndDetach:"].implementation, {
//     onEnter(args) {
//         logw(`\nCalled _initWithContext:bundleUnit:applicationRecord:bundleID:resolveAndDetach:`)
//         logw(`ins ${new ObjC.Object(args[0])}`)
//         // lfs(args[0])
//         // LSApplicationProxy ( 0x200d11ed8 ) -> LSBundleProxy ( 0x200d12ba8 ) -> LSResourceProxy ( 0x200d11e88 ) -> _LSQueryResult ( 0x200d12950 ) -> NSObject ( 0x200cfb260 )


//         // --- 0x200cfb288 & NSObject ---
//         // [ 0 ]   0x0 [ 0x282da1450 ] -> isa: | ObjC.Object <- class of LSApplicationProxy @ 0x200d11ed8
//         //         0x200d11eb0 -> LSApplicationProxy

//         // --- 0x200d11e60 & LSResourceProxy ---
//         // [ 0 ]   0x8 [ 0x282da1458 ] -> _localizedName: | object
//         //         null
//         // [ 1 ]   0x10 [ 0x282da1460 ] -> __boundIconInfo: | object
//         //         null

//         // --- 0x200d12b80 & LSBundleProxy ---
//         // [ 0 ]   0x18 [ 0x282da1468 ] -> _localizedShortName: | object
//         //         null
//         // [ 1 ]   0x20 [ 0x282da1470 ] -> _foundBackingBundle: | boolean
//         //         false
//         // [ 2 ]   0x21 [ 0x282da1471 ] -> _containerized: | boolean
//         //         false
//         // [ 3 ]   0x28 [ 0x282da1478 ] -> _bundleIdentifier: | object
//         //         null
//         // [ 4 ]   0x30 [ 0x282da1480 ] -> _bundleURL: | object
//         //         null
//         // [ 5 ]   0x38 [ 0x282da1488 ] -> _bundleExecutable: | object
//         //         null
//         // [ 6 ]   0x40 [ 0x282da1490 ] -> _bundleContainerURL: | object
//         //         null
//         // [ 7 ]   0x48 [ 0x282da1498 ] -> _bundleVersion: | object
//         //         null
//         // [ 8 ]   0x50 [ 0x282da14a0 ] -> _sdkVersion: | object
//         //         null
//         // [ 9 ]   0x58 [ 0x282da14a8 ] -> _signerIdentity: | object
//         //         null
//         // [ 10 ]  0x60 [ 0x282da14b0 ] -> _signerOrganization: | object
//         //         null
//         // [ 11 ]  0x68 [ 0x282da14b8 ] -> _cacheGUID: | object
//         //         null
//         // [ 12 ]  0x70 [ 0x282da14c0 ] -> _sequenceNumber: | object
//         //         0
//         // [ 13 ]  0x78 [ 0x282da14c8 ] -> _machOUUIDs: | object
//         //         null
//         // [ 14 ]  0x80 [ 0x282da14d0 ] -> _compatibilityState: | object
//         //         0
//         // [ 15 ]  0x88 [ 0x282da14d8 ] -> __infoDictionary: | object
//         //         null
//         // [ 16 ]  0x90 [ 0x282da14e0 ] -> __entitlements: | object
//         //         null
//         // [ 17 ]  0x98 [ 0x282da14e8 ] -> __environmentVariables: | object
//         //         null
//         // [ 18 ]  0xa0 [ 0x282da14f0 ] -> __validationToken: | object
//         //         null

//         // --- 0x200d11eb0 & LSApplicationProxy ---
//         // [ 0 ]   0xa8 [ 0x282da14f8 ] -> _deviceIdentifierVendorName: | object
//         //         null
//         // [ 1 ]   0xb0 [ 0x282da1500 ] -> _record: | object
//         //         null
//         // [ 2 ]   0xb8 [ 0x282da1508 ] -> _plugInKitPlugins: | object
//         //         null
//         // [ 3 ]   0xc0 [ 0x282da1510 ] -> _userInitiatedUninstall: | boolean
//         logw(`_initWithContext ${(args[2])}`)
//         logw(`bundleUnit ${(args[3])}`)
//         logw(`applicationRecord ${args[4]} ${new ObjC.Object(args[4])}`)
//         // m(args[4]) -> LSApplicationRecord
//         logw(`bundleID ${new ObjC.Object(args[5])}`)
//         logw(`resolveAndDetach ${(args[6])}`)
//     }
// })

// 拿到任意一个app的代理application对象
// ObjC.classes.LSApplicationProxy["applicationProxyForIdentifier:"]("com.apple.springboard")


// // -[SBSwitcherModifier loggingCategory]
// Interceptor.attach(ObjC.classes.SBSwitcherModifier["- loggingCategory"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled loggingCategory \n\t${ins} \n\t${sel}`)
//         printBacktrace(this.context)
//     }
// })

// // -[SBFluidSwitcherRootSwitcherModifier handleEvent:]
// Interceptor.attach(ObjC.classes.SBFluidSwitcherRootSwitcherModifier["- handleEvent:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])

//         logw(`\nCalled handleEvent: \n\t${ins} \n\t${sel} \n\t${new ObjC.Object(args[3])}`)
//        printBacktrace(this.context)
//     }
// })

// // -[SBMainWorkspace applicationProcessWillLaunch:0x14f135990]
// Interceptor.attach(ObjC.classes.SBMainWorkspace["- applicationProcessWillLaunch:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled applicationProcessWillLaunch: \n\t${ins} \n\t${sel}`)
//         printBacktrace(this.context)
//     }
// }) 

// // -[SBMainWorkspace applicationProcessDidExit:0x108f48430 withContext:0x281612380]
// Interceptor.attach(ObjC.classes.SBMainWorkspace["- applicationProcessDidExit:withContext:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled applicationProcessDidExit: \n\t${ins} \n\t${sel}`)
//         printBacktrace(this.context)
//     }
// })

// // -[FBProcess _notePendingExitForReason:0x1efac15d0]
// Interceptor.replace(ObjC.classes.FBProcess["- _notePendingExitForReason:"].implementation, new NativeCallback(function(a0,a1,a2){
//     logd(`called NOP _notePendingExitForReason: ${new ObjC.Object(a2)}`)
//     printBacktrace(this.context)
// }, 'void',['pointer','pointer','pointer']))

// -[FBSApplicationLibrary applicationsDidFailToInstall:0x281ca5f20]
// Interceptor.attach(ObjC.classes.FBSApplicationLibrary["- applicationsDidFailToInstall:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled applicationsDidFailToInstall: \n\t${ins} \n\t${sel} ${new ObjC.Object(args[2])}`)
//        printBacktrace(this.context)
//     }
// })

// _LSBundleIDValidationToken + supportsSecureCoding
// Interceptor.attach(ObjC.classes["_LSBundleIDValidationToken"]["+ supportsSecureCoding"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled supportsSecureCoding \n\t${ins} \n\t${sel}`)
//         printBacktrace(this.context)
//     },
//     onLeave(retval) {
//         logw(`\nReturned supportsSecureCoding \n\t${retval}`)
//         retval.replace(NULL)
//     }, 
// })


// -[MCInstallProfileViewController profileConnection:0x2825b2400 didFinishInstallationWithIdentifier:0x0 error:0x2805365b0]
// Interceptor.attach(ObjC.classes.MCInstallProfileViewController["- profileConnection:didFinishInstallationWithIdentifier:error:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const sel = ObjC.selectorAsString(args[1])
//         logw(`\nCalled profileConnection:didFinishInstallationWithIdentifier:error: \n\t${ins} \n\t${sel}`)
//         printBacktrace(this.context)
//     }
// })

// // // -[MCProfile isLocked]
// Interceptor.attach(ObjC.classes.MCProfile["- isLocked"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled isLocked ${ins}`)
//         printBacktrace(this.context)
//    },
//    onLeave(retval) {
//        logw(`\nReturned isLocked ${retval}`)
//    }
// })

// 0x1b690bdec
// new NativeFunction(ptr(0x1b690bdec), 'void', ['pointer', 'pointer', 'pointer', 'pointer'])(ptr(0x1ec0408c0), ptr(0x281ed4510), ptr(38), ptr(0))

// -[STTelephonyStateProvider setTelephonyDaemonRestartHandlerCanceled:0x0]
// Interceptor.attach(ObjC.classes.STTelephonyStateProvider["- setTelephonyDaemonRestartHandlerCanceled:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         const args2 = new ObjC.Object(args[2])
//         logw(`\nCalled setTelephonyDaemonRestartHandlerCanceled: \n\t${ins} ${args2}`)
//     }
// })

// // -[SBTelephonyManager _primarySubscriptionSlot]
// Interceptor.attach(ObjC.classes.SBTelephonyManager["- _primarySubscriptionSlot"].implementation, {
//     onEnter(args) {
//     },
//     onLeave(retval) {
//         logw(`\nReturned _primarySubscriptionSlot \n\t${retval}`)
//         logw(`${new ObjC.Object(retval)}`)
//     }
// })

// // -[MCProfile trustLevel]
// Interceptor.attach(ObjC.classes.MCProfile["- trustLevel"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled trustLevel ${ins}`)
//         printBacktrace(this.context)
//     },
//     onLeave(retval) {
//         logw(`\nReturned trustLevel \n\t${retval}`)
//     }
// })

// // -[STTelephonyStateProvider _handleTelephonyDaemonRestart]
// Interceptor.replace(ObjC.classes.STTelephonyStateProvider["- _handleTelephonyDaemonRestart"].implementation, new NativeCallback(function(a0,a1,a2){
//     logw(`\nCalled _handleTelephonyDaemonRestart \n\t${new ObjC.Object(a0)}`)
// }, 'void',['pointer','pointer','pointer']))

// // -[STTelephonyStateProvider isSIMPresentForSlot:0x2]
// Interceptor.attach(ObjC.classes.STTelephonyStateProvider["- isSIMPresentForSlot:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled isSIMPresentForSlot: \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturnedisSIMPresentForSlot: \n\t${retval}`)
//     }
// })

// // -[STTelephonySubscriptionInfo registrationStatus]
// Interceptor.attach(ObjC.classes.STTelephonySubscriptionInfo["- registrationStatus"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled registrationStatus \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned registrationStatus \n\t${retval}`)
//         retval.replace(ptr(1))
//     }
// })

// // -[STTelephonySubscriptionInfo cellularRegistrationStatus]
// Interceptor.attach(ObjC.classes.STTelephonySubscriptionInfo["- cellularRegistrationStatus"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled cellularRegistrationStatus \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned cellularRegistrationStatus \n\t${retval}`)
//         retval.replace(ptr(1))
//     }
// })

// // -[STTelephonySubscriptionInfo isPreferredForDataConnections]
// Interceptor.attach(ObjC.classes.STTelephonySubscriptionInfo["- isPreferredForDataConnections"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled isPreferredForDataConnections \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned isPreferredForDataConnections \n\t${retval}`)
//         retval.replace(ptr(1))
//     }
// })

// // -[STTelephonySubscriptionInfo SIMStatus]
// Interceptor.attach(ObjC.classes.STTelephonySubscriptionInfo["- SIMStatus"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled SIMStatus \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned SIMStatus \n\t${retval}`)
//         retval.replace(allocOCString("kCTSIMSupportSIMStatusNotReady").handle)
//     }
// })


// // -[MCProfileConnection mustInstallProfileNonInteractively:0x282d60380]
// Interceptor.attach(ObjC.classes.MCProfileConnection["- mustInstallProfileNonInteractively:"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled mustInstallProfileNonInteractively: \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned mustInstallProfileNonInteractively \n\t${retval}`)
//         retval.replace(ptr(1))
//     }
// })

// // -[MCProfileConnection isProfileUIInstallationEffectivelyAllowed]
// Interceptor.attach(ObjC.classes.MCProfileConnection["- isProfileUIInstallationEffectivelyAllowed"].implementation, {
//     onEnter(args) {
//         const ins = new ObjC.Object(args[0])
//         logw(`\nCalled isProfileUIInstallationEffectivelyAllowed \n\t${ins}`)
//     },
//     onLeave(retval) {
//         logw(`\nReturned isProfileUIInstallationEffectivelyAllowed \n\t${retval}`)
//     }
// })

