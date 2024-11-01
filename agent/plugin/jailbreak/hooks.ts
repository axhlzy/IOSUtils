// import { CTLT_YPE } from "./enum"

const SLOG: boolean = true // simple log

const checkIfContainJbPaths = (str: string): boolean => {
    // The string that may be detected
    const JbPaths = [
        "/Applications/Cydia.app",
        "/usr/sbin/sshd",
        "/bin/bash",
        "/etc/apt",
        "/Library/MobileSubstrate",
        "/User/Applications/",
        "/private/var/lib/apt/",
        "/private/var/lib/cydia/",
        "substitute",
        "substrate",
        "CepheiUI"
    ]
    return JbPaths.some(item => str.includes(item))
}

export const hook_stat = () => {
    logd("hook stat & lstat")

    // int stat(const char *, struct stat *)
    // 成功返回 0  失败返回 -1

    // #define __DARWIN_STRUCT_STAT64 { \
    // 	dev_t		st_dev;                 /* [XSI] ID of device containing file */ \ 设备编号
    // 	mode_t		st_mode;                /* [XSI] Mode of file (see below) */ \  文件类型及权限
    // 	nlink_t		st_nlink;               /* [XSI] Number of hard links */ \ 硬链接数量
    // 	__darwin_ino64_t st_ino;                /* [XSI] File serial number */ \ inode 编号
    // 	uid_t		st_uid;                 /* [XSI] User ID of the file */ \ 拥有者的用户 ID
    // 	gid_t		st_gid;                 /* [XSI] Group ID of the file */ \ 拥有者的组 ID
    // 	dev_t		st_rdev;                /* [XSI] Device ID */ \
    // 	__DARWIN_STRUCT_STAT64_TIMES \
    // 	off_t		st_size;                /* [XSI] file size, in bytes */ \ 文件大小（以字节为单位）
    // 	blkcnt_t	st_blocks;              /* [XSI] blocks allocated for file */ \
    // 	blksize_t	st_blksize;             /* [XSI] optimal blocksize for I/O */ \
    // 	__uint32_t	st_flags;               /* user defined flags for file */ \
    // 	__uint32_t	st_gen;                 /* file generation number */ \
    // 	__int32_t	st_lspare;              /* RESERVED: DO NOT USE! */ \
    // 	__int64_t	st_qspare[2];           /* RESERVED: DO NOT USE! */ \
    // }

    const addr = Module.findExportByName("libsystem_kernel.dylib", "stat")!
    Interceptor.attach(addr, {
        onEnter(args) {
            this.disp = `stat ( '${args[0].readCString()}', ${args[1]} )`
        },
        onLeave(retval) {
            if (checkIfContainJbPaths(this.disp)) {
                loge(`${retval} <= ${this.disp}`)
                retval.replace(ptr(-1))
            } else {
                if (!SLOG) logd(`${retval} <= ${this.disp}`)
            }
        }
    })

    // int     lstat(const char *, struct stat *) __DARWIN_INODE64(lstat);
    const addr2 = Module.findExportByName("libsystem_kernel.dylib", "lstat")!
    Interceptor.attach(addr2, {
        onEnter(args) {
            this.disp = `lstat ( '${args[0].readCString()}', ${args[1]} )`
        },
        onLeave(retval) {
            if (checkIfContainJbPaths(this.disp)) {
                loge(`${retval} <= ${this.disp}`)
                retval.replace(ptr(-1))
            } else {
                if (!SLOG) logd(`${retval} <= ${this.disp}`)
            }
        }
    })

}

const hook_NSString_IsEqualToString = () => {
    logd("hook NSString_IsEqualToString")
    const addr = ptr(ObjC.classes["NSString"]["- isEqualToString:"].implementation)
    Interceptor.attach(addr, {
        onEnter(args) {
            logw("NSString - isEqualToString")
            let thiz = new ObjC.Object(args[0])
            let SEL = ObjC.selectorAsString(args[1])
            let str = new ObjC.Object(args[1]).toString()
            this.disp = `${thiz} ${SEL} ${str}`
        },
        onLeave(retval) {
            if (checkIfContainJbPaths(this.disp)) {
                loge(`${retval} <= ${this.disp}`)
            } else {
                if (!SLOG) logd(`${retval} <= ${this.disp}`)
            }
        }
    })
}

// dladdr
const hook_dladdr = () => {
    const addr = Module.findExportByName("libsystem_kernel.dylib", "dladdr")!
    Interceptor.attach(addr, {
        onEnter(args) {

            // typedef struct dl_info {
            //         const char      *dli_fname;     /* Pathname of shared object */
            //         void            *dli_fbase;     /* Base address of shared object */
            //         const char      *dli_sname;     /* Name of nearest symbol */
            //         void            *dli_saddr;     /* Address of nearest symbol */
            // } Dl_info;

            this.disp = `dladdr ( ${args[0]}, ${args[1]} )`
        },
        onLeave(retval) {
            if (checkIfContainJbPaths(this.disp)) { }
        }
    })
}

// hook isDebugged
// 校验当前进程是否为调试模式，hook sysctl方法可以绕过
// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
// Thanks to https://developer.apple.com/library/archive/qa/qa1361/_index.html

// sysctl 是一个用于查询和设置内核参数的系统调用。它主要用于获取或更改系统信息，例如 CPU 类型、内存大小，以及其他系统级别的配置
// int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
// 成功返回 0 失败返回 -1

/**
 * IMPL ↓
 * BOOL isDebugged()
{
    int junk;
    int mib[4];
    struct kinfo_proc info;
    size_t size;
    info.kp_proc.p_flag = 0; // 指向存储查询结果的缓冲区的指针,如果只是想设置系统参数,设置为NULL
    mib[0] = CTL_KERN;  // 整数数组，用于指定要查询或设置的系统参数 0x4
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
}
 */

// Process.enumerateModules()
//     .forEach(module => {
//         module.enumerateSymbols()
//         .forEach(symbol => {
//             if (symbol.name.includes("sysctl") && !symbol.address.isNull()) {
//                 logd(`${symbol.address} <= ${symbol.name}`)
//             }
//         })
//     })

const hook_isDebugged = () => {
    logd("hook sysctl | isDebugged")

    let addr_sysctl = Module.findExportByName("libsystem_c.dylib", "sysctl")!

    // addr_sysctl = DebugSymbol.fromName("sysctl").address <- 这里被坑了 重名符号 返回的是最后一个

    // DebugSymbol.fromName("sysctl")
    // {
    //     "address": "0x101214e30",
    //     "column": 0,
    //     "fileName": "",
    //     "lineNumber": 0,
    //     "moduleName": "dyld",
    //     "name": "sysctl"
    // }

    Interceptor.attach(addr_sysctl, {
        onEnter(args) {
            // junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
            // int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
            this.disp = `  ( name=${args[0]}, namelen=${args[1]}, oldp=${args[2]}, oldlenp=${args[3]}, newp=${args[4]}, newlen${args[5]} )`
            let tmp: string = ''
            for (let i = 0; i < args[1].toInt32(); i++) {  // int* ++
                // if (i == 0) {
                //     tmp += `${CTLT_YPE[args[0].readInt()].toString()} | `
                // } else {
                tmp += `${[args[0].add(i).readInt()].toString()} | `
                // }
            }
            this.disp1 = tmp.substring(0, tmp.length - 3)
            this.info = args[2]
        },
        onLeave(retval) {
            logd(`${retval} <= ${this.disp}`)
            logz(`\t${this.disp1}`)

            // struct kinfo_proc {
            // struct  extern_proc kp_proc;                    /* proc structure */
            // struct  eproc {
            // 	struct  proc *e_paddr;          /* address of proc */
            // 	struct  session *e_sess;        /* session pointer */
            // 	struct  _pcred e_pcred;         /* process credentials */

            // 由上可见就是第一个结构体

            // struct extern_proc {
            // 	union {
            // 		struct {
            // 			struct  proc *__p_forw; /* Doubly-linked run/sleep queue. */
            // 			struct  proc *__p_back;
            // 		} p_st1;
            // 		struct timeval __p_starttime;   /* process start time */
            // 	} p_un;
            // #define p_forw p_un.p_st1.__p_forw
            // #define p_back p_un.p_st1.__p_back
            // #define p_starttime p_un.__p_starttime
            // 	struct  vmspace *p_vmspace;     /* Address space. */
            // 	struct  sigacts *p_sigacts;     /* Signal actions, state (PROC ONLY). */
            // 	int     p_flag;                 /* P_* flags. */

            // (lldb) p/a &(info.kp_proc)
            // (extern_proc *) 0x000000016ef08ef0
            // (lldb) p/a &(info.kp_proc.p_flag)
            // (int *) 0x000000016ef08f10
            // ofset 0x20 = pointersize * 4

            // p/x info.kp_proc.p_flag => (int) 0x04004804
            // p/x  ~0x800 & 0x04004804 

            // #define P_TRACED        0x00000800      /* Debugged process being traced */
            let p_flag_addr = ptr(this.info).add(Process.pointerSize * 4)
            logz(`\t${p_flag_addr} => ${p_flag_addr.readPointer()}`)
            if (p_flag_addr.readInt() & 0x00000800) {
                loge(`\t! bypass isDebug`)
                p_flag_addr.writePointer(p_flag_addr.readPointer().and(~0x00000800))
            }
        }
    })

}

// _dyld_get_image_name
const hook_get_image_name = () => {
    logd("hook dyld_get_image_name")

    // extern const char* _dyld_get_image_name(uint32_t image_index) 
    // __OSX_AVAILABLE_STARTING(__MAC_10_1, __IPHONE_2_0);
    const addr = Module.findExportByName("libdyld.dylib", "_dyld_get_image_name")!
    Interceptor.attach(addr, {
        onEnter(args) {
            this.disp = `dyld_get_image_name ( index=${args[0]} | ${args[0].toInt32()} )`
        },
        onLeave(retval) {
            const ret_str = retval.readCString()
            if (ret_str == null) return
            const disp_str = `${this.disp} => '${ret_str}'`
            if (!SLOG) logd(disp_str)
            if (ret_str.includes("substitute")
                || ret_str.includes("substrate")
                || ret_str.includes("CepheiUI")
            ) {
                loge(disp_str)
                const new_ret = ret_str
                    .replace("substitute", "---")
                    .replace("substrate", "---")
                    .replace("CepheiUI", "---")
                retval.replace(Memory.allocUtf8String(new_ret))
                logd('called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n') + '\n')
                return
            }
        }
    })

}

const hook_canOpenURL = () => {
    logd("hook canOpenURL")

    const old_Method_canOpenURL = ObjC.classes["UIApplication"]["- canOpenURL:"]
    const old_impl = old_Method_canOpenURL.implementation
    old_Method_canOpenURL.implementation = ObjC.implement(old_Method_canOpenURL,
        function (clazz, selector, URLString) {
            // [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.avl.com"]]
            const disp = `canOpenURL ( ${new ObjC.Object(clazz)}, ${ObjC.selectorAsString(selector)}, ${new ObjC.Object(URLString)} )` as string
            let retval = old_impl(clazz, selector, URLString) as number
            if (disp.includes("cydia") || disp.includes("Cydia")) {
                loge(`${retval} <= ${disp}`)
                retval = 0
            } else {
                if (!SLOG) logd(`${retval} <= ${disp}`)
            }
            return retval
        })
}

const hook_URLWithString = () => {
    logd("hook URLWithString")

    const old_func = ObjC.classes.NSURL.URLWithString_
    const old_impl = old_func.implementation
    old_func.implementation = ObjC.implement(old_func, function (clazz, selector, URLString) {
        let toCString: string = new ObjC.Object(URLString).toString()
        const disp: string = `URLWithString ( '${toCString}' )`
        if (disp.includes("cydia")) {
            URLString = ObjC.classes.NSString.stringWithString_(toCString.replace("cydia", "ccc"))
            loge(`${disp}`)
        } else {
            if (!SLOG) logd(`${disp}`)
        }
        return old_impl(clazz, selector, URLString)
    })
}

const hook_NSFileManager = () => {
    logd("hook NSFileManager")

    const isOpenJailFile = [
        "/Application/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/tmp/cydia.log",
        "/Applications/WinterBoard.app",
        "/var/lib/cydia",
        "/private/etc/dpkg/origins/debian",
        "/bin.sh",
        "/private/etc/apt",
        "/etc/ssh/sshd_config",
        "/private/etc/ssh/sshd_config",
        "/Applications/SBSetttings.app",
        "/private/var/mobileLibrary/SBSettingsThemes/",
        "/private/var/stash",
        "/usr/libexec/sftp-server",
        "/usr/libexec/cydia/",
        "/usr/sbin/frida-server",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/Applications/FakeCarrier.app",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/usr/libexec/ssh-keysign",
        "/usr/libexec/sftp-server",
        "/Applications/blackra1n.app",
        "/Applications/IntelliScreen.app",
        "/Applications/Snoop-itConfig.app",
        "/var/lib/dpkg/info",
        "/Applications/Icy.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/bin/sh",
        "/usr/bin/ssh",
        "/usr/bin/sshd",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/log/syslog",
        "/var/tmp/cydia.log",
    ]

    // - fileExistsAtPath:isDirectory:
    // - (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(nullable BOOL *)isDirectory;
    const old_func = ObjC.classes.NSFileManager["- fileExistsAtPath:isDirectory:"]
    const old_impl = old_func.implementation
    old_func.implementation = ObjC.implement(old_func, function (clazz, selector, fileExistsAtPath, isDirectory) {
        if (!fileExistsAtPath) return old_impl(clazz, selector, fileExistsAtPath, isDirectory)
        const toCString: string = new ObjC.Object(fileExistsAtPath).toString()
        const disp: string = `fileExistsAtPath:isDirectory: ( '${toCString}', ${isDirectory} )`
        if (isOpenJailFile.includes(toCString)) {
            loge(`${disp}`)
            // fileExistsAtPath = ObjC.classes.NSString.stringWithString_("zzzz")
            return 0
        } else if (!SLOG) {
            logd(`${disp}`)
        }
        return old_impl(clazz, selector, fileExistsAtPath, isDirectory)
    })

    // fopen
    // FILE	*fopen(const char * __restrict __filename, const char * __restrict __mode)
    Interceptor.attach(Module.findExportByName("libsystem_c.dylib", "fopen")!, {
        onEnter(args) {
            const fileName = args[0].readCString()
            if (fileName != null) {
                const disp = `fopen ( ${fileName} )`
                if (isOpenJailFile.includes(fileName)) {
                    loge(`${disp}`)
                    args[0] = Memory.allocUtf8String("zzzz")
                } else if (!SLOG) {
                    logd(`${disp}`)
                }
            }
        }
    })
}

const hook_getenv = () => {
    logd("hook getenv")

    // getenv
    // char	*getenv(const char *);
    Interceptor.attach(Module.findExportByName("libsystem_c.dylib", "getenv")!, {
        onEnter(args) {
            this.envName = args[0].readCString()
        },
        onLeave(retval) {
            const disp = `getenv ( ${this.envName} ) | ret: '${retval.readCString()}'`
            if (this.envName != null && this.envName == "DYLD_INSERT_LIBRARIES") {
                loge(`${disp}`)
                retval.replace(NULL)
                logd('called from:\n' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n') + '\n')
            } else if (!SLOG) {
                logd(`${disp}`)
            }
        }
    })
}

const hook_ptrace = () => {
    logd("hook ptrace")

    // void mRiYXNnZnZmZGF2Ym() {
    //     // No Need to encode these strings, because they will be directly compiled, they are not going to be present in the 'DATA' segment of the binary.
    //     __asm (
    //         "mov r0, #31\n" // set #define PT_DENY_ATTACH (31) to r0
    //         "mov r1, #0\n"   // clear r1
    //         "mov r2, #0\n"   // clear r2
    //         "mov r3, #0\n"   // clear r3
    //         "mov ip, #26\n"  // set the instruction pointer to syscal 26
    //         "svc #0x80\n"    // SVC (formerly SWI) generates a supervisor call. Supervisor calls are normally used to request privileged operations or access to system resources from an operating system
    //         );
    // }

    // ptrace(PT_DENY_ATTACH, 0, 0, 0);
    // ↑ 还有可能是使用系统调用实现 这里不做处理 trace指令查看svc调用 不在这里实现 ↑

    // int ptrace(int request, pid_t pid, caddr_t addr, int data);
    // #define PT_DENY_ATTACH 31
    const PT_DENY_ATTACH = 31
    const addr = Module.findExportByName("libsystem_kernel.dylib", "ptrace")!
    const srcCall = new NativeFunction(addr, "int", ["int", "int", "pointer", "int"])
    Interceptor.revert(addr)
    Interceptor.replace(addr, new NativeCallback((request, pid, addr, data) => {
        loge(`called ptrace( ${request}, ${pid}, ${addr}, ${data} )`)
        if (request == PT_DENY_ATTACH) return 0
        return srcCall(request, pid, addr, data)
    }, "int", ["int", "int", "pointer", "int"]))
}

const hook_NSClassFromString = () => {
    logd("hook NSClassFromString")

    // 从类名获取类 类似java的Class.forName
    const checkArray = [
        "HBPreferences", // 用于以越狱环境下从偏好设置读取配置项
    ]

    // FOUNDATION_EXPORT Class _Nullable NSClassFromString(NSString *aClassName);
    Interceptor.attach(Module.findExportByName("Foundation", "NSClassFromString")!, {
        onEnter(args) {
            // Foundation -> -[NSString(NSStringOtherEncodings) UTF8String]
            try {
                // this.className = new ObjC.Object(args[0]).UTF8String()
                this.className = new ObjC.Object(args[0]).toString()
            } catch (error) {
                this.className = ''
            }
        },
        onLeave(retval) {
            if (checkArray.includes(this.className)) {
                loge(`${retval} <= NSClassFromString( '${this.className}' )`)
                retval.replace(NULL)
            } else {
                if (!SLOG) logw(`${retval} <= ${this.className}`)
            }
        }
    })
}

declare global {
    var hook_all_detect: () => void
    var hook_stat: () => void
    var hook_NSString_IsEqualToString: () => void
    var hook_isDebugged: () => void
    var hook_get_image_name: () => void
    var hook_canOpenURL: () => void
    var hook_URLWithString: () => void
    var hook_NSFileManager: () => void
    var hook_getenv: () => void
    var hook_ptrace: () => void
    var hook_NSClassFromString: () => void

    var hook_exit: () => void
    var hook_strcmp: ()=> void
}

globalThis.hook_all_detect = () => {
    hook_stat()
    // hook_NSString_IsEqualToString()
    // hook_isDebugged()
    hook_get_image_name()
    hook_canOpenURL()
    hook_URLWithString()
    hook_NSFileManager()
    hook_getenv()
    hook_ptrace()
    hook_NSClassFromString()
}

globalThis.hook_stat = hook_stat
globalThis.hook_NSString_IsEqualToString = hook_NSString_IsEqualToString
globalThis.hook_isDebugged = hook_isDebugged
globalThis.hook_get_image_name = hook_get_image_name
globalThis.hook_canOpenURL = hook_canOpenURL
globalThis.hook_URLWithString = hook_URLWithString
globalThis.hook_NSFileManager = hook_NSFileManager
globalThis.hook_getenv = hook_getenv
globalThis.hook_ptrace = hook_ptrace
globalThis.hook_NSClassFromString = hook_NSClassFromString

globalThis.hook_exit = () => {
    Interceptor.attach(Module.findExportByName(null, "exit")!, {
        onEnter(args) {
            const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t")
            console.warn("\n[-] ======== Backtrace Start  ========")
            console.log(backtrace)
            console.warn("\n[-] ======== Backtrace End  ========")
        },
    })
}

globalThis.hook_strcmp = ()=>{
    Interceptor.attach(Module.findExportByName(null, "strcmp")!, {
        onEnter(args) {
            const arg0 = args[0].readCString()
            const arg1 = args[1].readCString()
            logd(`strcmp ( ${arg0}, ${arg1} )`)
        },
    })
}

// if (ObjC.available) {
//     const NSString = ObjC.classes.NSString
//     Interceptor.attach(NSString["- isEqualToString:"].implementation, {
//         onEnter: function (args) {
//             // args[0] 是 'self'
//             // args[1] 是 '_cmd'（这里的命令或方法选择器）
//             // args[2] 是与之比较的 NSString 对象
//             const selfStr = new ObjC.Object(args[0]).toString()
//             const compareStr = new ObjC.Object(args[2]).toString()
//             this.passStr = `'${selfStr}', '${compareStr}'`
//         },
//         onLeave: function (retval) {
//             logd(`isEqualToString: ( ${this.passStr}) | Returns ${retval}`)
//         }
//     })
// } else {
//     loge("Objective-C runtime is not available.")
// }