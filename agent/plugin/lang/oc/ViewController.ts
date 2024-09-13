export { }

const hook_ViewController = () => {

    {
        // enter ↓

        // - presentViewController:animated:completion:
        Interceptor.attach(ObjC.classes["UIViewController"]["- presentViewController:animated:completion:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled presentViewController:'${instance}' -> '${new ObjC.Object(args[2])}' animated:'${args[3]}' completion:${args[4]}`)
                const _storyboard = instance.$ivars["_storyboard"]
                const _modalPresentationStyle = instance.$ivars["_modalPresentationStyle"]
                logz(`\t_storyboard:${_storyboard} | _modalPresentationStyle:${_modalPresentationStyle}`)
            }
        })

        // - presentViewController:withTransition:completion:
        Interceptor.attach(ObjC.classes["UIViewController"]["- presentViewController:animated:completion:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled presentViewController:'${instance}' -> '${new ObjC.Object(args[2])}' withTransition:'${args[3]}' completion:${args[4]}`)
                const _storyboard = instance.$ivars["_storyboard"]
                const _modalPresentationStyle = instance.$ivars["_modalPresentationStyle"]
                logz(`\t_storyboard:${_storyboard} | _modalPresentationStyle:${_modalPresentationStyle}`)
            }
        })

    }

    {
        // exit ↓

        // - dismissModalViewControllerAnimated:
        Interceptor.attach(ObjC.classes["UIViewController"]["- dismissModalViewControllerAnimated:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled dismissModalViewControllerAnimated:'${instance}' animated:'${args[2]}'`)
            }
        })

        // - dismissModalViewControllerWithTransition:
        Interceptor.attach(ObjC.classes["UIViewController"]["- dismissModalViewControllerWithTransition:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled dismissModalViewControllerWithTransition:'${instance}' Transition:'${args[2]}'`)
            }
        })

        // - dismissViewControllerAnimated:completion:
        Interceptor.attach(ObjC.classes["UIViewController"]["- dismissViewControllerAnimated:completion:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled dismissViewControllerAnimated:'${instance}' Animated:'${args[2]}' completion:'${args[3]}'`)
            }
        })

        // - dismissViewControllerWithTransition:completion:
        Interceptor.attach(ObjC.classes["UIViewController"]["- dismissViewControllerWithTransition:completion:"].implementation, {
            onEnter(args) {
                const instance = new ObjC.Object(args[0])
                logd(`\nCalled dismissViewControllerWithTransition:'${instance}' Transition:'${args[2]}' completion:'${args[3]}'`)
            }
        })

    }
}

const hook_UIAlertController = ()=>{

    // UIAlertController + alertControllerWithTitle:message:preferredStyle:
    Interceptor.attach(ObjC.classes["UIAlertController"]["+ alertControllerWithTitle:message:preferredStyle:"].implementation, {
        onEnter(args) {
            const title = new ObjC.Object(args[2])
            const msg = new ObjC.Object(args[3])
            logd(`\nCalled alertControllerWithTitle:'${title}' message:'${msg}' preferredStyle:${args[4]}`)
        }, onLeave(retval) {
            const instance :ObjC.Object = new ObjC.Object(retval)
            const _actions = instance.$ivars["_actions"] as ObjC.Object
            const count = _actions["- count"]()
            logz(`\t${instance} | actions:${_actions.handle} [ ${count} ]`)
        }
    })

    // UIAlertController - addAction:
    Interceptor.attach(ObjC.classes["UIAlertController"]["- addAction:"].implementation, {
        onEnter(args) {
            const instance = new ObjC.Object(args[0])
            const action = new ObjC.Object(args[2])
            logd(`\nCalled UIAlertController '${instance}' - addAction:'${action}'`)
            this.ins = instance
        }, onLeave(retval) {
            const instance = this.ins as ObjC.Object
            const _actions = instance.$ivars["_actions"] as ObjC.Object
            const count = _actions["- count"]()
            logz(`\t${instance} | actions:${_actions} [ ${count} ]`)
        }
    })

    // UIAlertAction + actionWithTitle:style:handler:
    Interceptor.attach(ObjC.classes["UIAlertAction"]["+ actionWithTitle:style:handler:"].implementation, {
        onEnter(args) {
            const title = new ObjC.Object(args[2])
            // !todo parse Block
            logd(`\nCalled UIAlertAction actionWithTitle:'${title}' style:'${args[3]}' handler:'${new ObjC.Block(args[4])}'`)
        }
    })

    // var newReplyBlock = new ObjC.Block({
    //     retType: 'void',
    //     argTypes: ['int', 'pointer'],
    //     implementation: function (successOrFailure, nsError) {
    //         console.log("Success: "+successOrFailure)
    //     }
    // });
}

declare global {
    var hook_ViewController: () => void
    var hook_UIAlertController: () => void
}

globalThis.hook_ViewController = hook_ViewController
globalThis.hook_UIAlertController = hook_UIAlertController