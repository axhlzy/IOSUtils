// import { CTLT_YPE } from "./enum"

// The string that may be detected
const JbPaths = [
    "/Applications/Cydia.app",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/etc/apt",
    "/Library/MobileSubstrate",
    "/User/Applications/"
]

const detectedArray: string[] = [
    "Cydia",
]

const checkIfContainJbPaths = (str: string): boolean => {
    return JbPaths.some(item => str.includes(item))
}

export const hook_stat = () => {

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
                logd(`${retval} <= ${this.disp}`)
            }
        }
    })
    
}

const hook_NSString_IsEqualToString = ()=>{
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
                logd(`${retval} <= ${this.disp}`)
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
            if (checkIfContainJbPaths(this.disp)) {}
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
    logd("hook_isDebugged")

    // DebugSymbol.fromName("sysctl")
    // {
    //     "address": "0x101214e30",
    //     "column": 0,
    //     "fileName": "",
    //     "lineNumber": 0,
    //     "moduleName": "dyld",
    //     "name": "sysctl"
    // }

    let addr_sysctl = Module.findExportByName("libsystem_c.dylib", "sysctl")!
    
    // addr_sysctl = DebugSymbol.fromName("sysctl").address <- 这里被坑了 重名符号 返回的是最后一个

    Interceptor.attach(addr_sysctl, {
        onEnter(args) {

            logw("ENTER sysctl")

            // junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
            // int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
            this.disp = `sysctl ( name=${args[0]}, namelen=${args[1]}, oldp=${args[2]}, oldlenp=${args[3]}, newp=${args[4]}, newlen${args[5]} )`
            let tmp :string = ''
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
            logd(`${p_flag_addr} => ${p_flag_addr.readPointer()}`)
            if (p_flag_addr.readInt() & 0x00000800) {
                loge(`! isDebugged`)
                p_flag_addr.writePointer(p_flag_addr.readPointer().and(~0x00000800))
            }
        }
    })

}

declare global {
    var hook_stat: () => void
    var hook_NSString_IsEqualToString: () => void
    var hook_isDebugged: () => void
}

globalThis.hook_stat = hook_stat
globalThis.hook_NSString_IsEqualToString = hook_NSString_IsEqualToString
globalThis.hook_isDebugged = hook_isDebugged