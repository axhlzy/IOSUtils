const test_SBIcon = () => {

    // -[SBIconController allowsUninstall]
    Interceptor.attach(ObjC.classes["SBIconController"]["- allowsUninstall"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            loge(`\nCalled SBIconController ${ins} ${sel}`)
        },
        onLeave(retval) {
            loge(`\nSBIconController allowsUninstall => ${retval}`)
        }
    })

    // -[SBIcon isUninstallSupported]
    Interceptor.attach(ObjC.classes["SBIcon"]["- isUninstallSupported"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            loge(`\nCalled SBIcon ${ins}`)
        },
        onLeave(retval) {
            loge(`\SBIcon isUninstallSupported => ${retval}`)
        }
    })


    // -[SBHIconManager removeIcon:0x2815e5680 options:0x1 completion:0x16d556400]
    Interceptor.attach(ObjC.classes["SBHIconManager"]["- removeIcon:options:completion:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            logd(`\nCalled SBHIconManager ${ins} ${args[2]} ${args[3]} ${args[4]}`)
            printBacktrace(this.context)
        }
    })

    // -[SBIconListModel icons]
    Interceptor.attach(ObjC.classes["SBIconListModel"]["- icons"].implementation, {
        onEnter(args) {
        },
        onLeave(retval) {
            // lfs(retval)   
            const arr = new ObjC.Object(retval)
            const c = Number.parseInt(arr["- count"]())
            let m: number = c
            for (let i = 0; i < m; i++) {
                logw(arr["- objectAtIndex:"](i))
            }
        }
    })

    // -[MCRemoveProfileViewController initWithProfile:0x28063ce00]
    Interceptor.attach(ObjC.classes["MCRemoveProfileViewController"]["- initWithProfile:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            logd(`\nCalled MCRemoveProfileViewController ${ins} ${args[2]}`)
            printBacktrace(this.context)
        }
    })

    // -[MCInstallProfileViewController initWithProfile:0x283058fc0 viewMode:0x1]
    Interceptor.attach(ObjC.classes["MCInstallProfileViewController"]["- initWithProfile:viewMode:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            logd(`\nCalled MCInstallProfileViewController ${ins} ${args[2]} ${args[3]}`)
            printBacktrace(this.context)
        }
    })

    // -[MCInstallProfileViewController initWithInstallableProfileData:fromSource:]
    Interceptor.attach(ObjC.classes["MCInstallProfileViewController"]["- initWithInstallableProfileData:fromSource:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            logd(`\nCalled MCInstallProfileViewController ${ins} ${args[2]} ${args[3]}`)
            printBacktrace(this.context)
        }
    })


    // -[_UIContextMenuActionsListView setDelegate:0x109246440]
    Interceptor.attach(ObjC.classes["_UIContextMenuActionsListView"]["- setDelegate:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const setDelegate = new ObjC.Object(args[2])
            logz(`\nCalled _UIContextMenuActionsListView ${ins} ${sel} \nsetDelegate:'${setDelegate}'`)
            // lfs(args[2])
        }
    })

    // -[SBBookmark iconCompleteUninstall:0x280aa2b80]
    Interceptor.attach(ObjC.classes["SBBookmark"]["- iconCompleteUninstall:"].implementation, {
        onEnter(args) {
            const ins = new ObjC.Object(args[0])
            const sel = ObjC.selectorAsString(args[1])
            const s = new ObjC.Object(args[2])
            logz(`\nCalled SBBookmark ${ins} ${sel} \iconCompleteUninstall:'${s}'`)
            let logs = `called from:\n${Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t')}\n`
            log(logs)
        }
    })

    // -[SBIconListModel numberOfIcons]
    Interceptor.attach(ObjC.classes["SBIconListModel"]["- numberOfIcons"].implementation, {
        onEnter(args) {
            logw(`SBIconListModel numberOfIcons ins ${args[0]}`)
        },
        onLeave(retval) {
            logw(`SBIconListModel numberOfIcons => ${retval}`)
        }
    })

    // -[SBRootFolderWithDock todayList]
    Interceptor.attach(ObjC.classes["SBRootFolderWithDock"]["- todayList"].implementation, {
        onEnter(args) {
            console.warn(`SBRootFolderWithDock todayList ins ${args[0]}`)
        },
        onLeave(retval) {
            ObjC.choose(ObjC.classes["SBBookmarkIcon"], {
                onMatch(item) {
                    LOGJSON(item)
                },
                onComplete() {

                }
            })
        }
    })


}