globalThis.hook_dialog = (printBackTrace: boolean = true) => {
    if (ObjC.available) {
        try {
            // Get the UIAlertController class
            const UIAlertController = ObjC.classes.UIAlertController

            // Hook +[UIAlertController alertControllerWithTitle:message:preferredStyle:]
            const alertControllerWithTitle_ptr = UIAlertController["+ alertControllerWithTitle:message:preferredStyle:"].implementation
            if (alertControllerWithTitle_ptr) {
                Interceptor.attach(alertControllerWithTitle_ptr, {
                    onEnter: function (args) {
                        logw(`[+] +[UIAlertController alertControllerWithTitle:message:preferredStyle:] called`)
                        // args[0] is the self (UIAlertController class)
                        // args[1] is the selector (+ alertControllerWithTitle:message:preferredStyle:)
                        // args[2] is the title (NSString)
                        // args[3] is the message (NSString)
                        // args[4] is the preferredStyle (UIAlertControllerStyle, an integer)

                        const title = new ObjC.Object(args[2]).toString()
                        const message = new ObjC.Object(args[3]).toString()
                        const preferredStyle = args[4].toInt32() // 0 for ActionSheet, 1 for Alert
                        
                        logw(`  Title: "${title}"`)
                        logd(`  Message: "${message}"`)
                        logd(`  Preferred Style: ${preferredStyle === 0 ? 'ActionSheet' : (preferredStyle === 1 ? 'Alert' : 'Unknown')}`)

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }
                    }
                })
                logd("[+] Successfully hooked +[UIAlertController alertControllerWithTitle:message:preferredStyle:]")
            } else {
                logw("[-] Could not find implementation for +[UIAlertController alertControllerWithTitle:message:preferredStyle:].")
            }

            // Optional: Hook -[UIViewController presentViewController:animated:completion:]
            // This hooks when the alert is actually presented
            const UIViewController = ObjC.classes.UIViewController
            const presentViewController_ptr = UIViewController["- presentViewController:animated:completion:"].implementation
            if (presentViewController_ptr) {
                Interceptor.attach(presentViewController_ptr, {
                    onEnter: function (args) {
                        // args[0] is the presenting UIViewController instance
                        // args[1] is the selector (- presentViewController:animated:completion:)
                        // args[2] is the viewControllerToPresent (UIViewController instance)
                        const viewControllerToPresent = new ObjC.Object(args[2])
                        // Check if the presented view controller is a UIAlertController
                        if (viewControllerToPresent.isKindOfClass_(UIAlertController)) {
                            logw(`[+] -[UIViewController presentViewController:animated:completion:] called to present a UIAlertController`)
                            // You can get the title and message from the UIAlertController instance here
                            const title = viewControllerToPresent.title().toString()
                            const message = viewControllerToPresent.message().toString()
                            logd(`  Alert Title: "${title}"`)
                            logd(`  Alert Message: "${message}"`)

                            if (printBackTrace) {
                                logo("Call Stack:")
                                logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                                logd("--------------------")
                            }
                        }
                    }
                })
                logd("[+] Successfully hooked -[UIViewController presentViewController:animated:completion:] for UIAlertController")
            } else {
                logw("[-] Could not find implementation for -[UIViewController presentViewController:animated:completion:].")
            }


        } catch (e) {
            loge("[-] Error hooking UIAlertController methods:" + e)
        }
    } else {
        loge("[-] Objective-C runtime not available")
    }

}

export { }

declare global {
    var hook_dialog: () => void
}