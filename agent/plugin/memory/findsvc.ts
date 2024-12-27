var targetPointers = new Array<NativePointer>()

globalThis.findSvcInstructions = (md: string = '') => {

    (md != '' ? Process.findModuleByName(md)! : Process.mainModule)
        .enumerateSections()
        .forEach(item => {
            if (item.name == '__text') {
                logw(`\n${item.address} -> ${item.name} ${ptr(item.size)}\n`)
                Memory.scanSync(item.address, item.size, "01 10 00 D4").forEach((item, index) => {
                    logd(`[${index}] ->\t${item.address.sub(Process.mainModule.base)} | ${DebugSymbol.fromAddress(item.address)}`)

                    if (!targetPointers.includes(item.address)) targetPointers.push(item.address)

                    let currentIns = Instruction.parse(item.address)
                    let lastIns: Arm64Instruction
                    let itorAdd = item.address

                    let maxItor = 5
                    let insLog: string = `\n\t${currentIns.address} ${currentIns}`
                    try {
                        while ((itorAdd = itorAdd.sub(0x4)) && --maxItor > 0) {
                            lastIns = Instruction.parse(itorAdd) as Arm64Instruction
                            if (lastIns.mnemonic == "mov" && lastIns.operands.find(i => i.type == "reg" && (i.value == "w16" || i.value == "x16"))) {
                                let opCode = Number(lastIns.operands.find(i => i.type == "imm")?.value)
                                insLog = `\n\t${lastIns.address} ${lastIns} | { ${SYSCALL[opCode]} [ ${opCode} ] ` + insLog
                                break
                            } else {
                                insLog = `\n\t${lastIns.address} ${lastIns}` + insLog
                            }
                        }
                    } catch (error) {

                    }
                    
                    if(!insLog.includes("| { ")) insLog = `\n\t ......` + insLog
                    insLog.split("\n")
                        .forEach(msg => msg.includes("svc") || msg.includes("| { ") ? logw(!msg.includes("svc") ? msg : msg + '\n') : logz(msg))

                    // MemoryAccessMonitor.enable({base:currentIns.address, size:0x4}, {
                    //     onAccess(details) {
                    //         logd(`${details.from}`)
                    //         LOGJSON(details)   
                    //     }
                    // })
                })
                newLine()
            }
        })
}

globalThis.findBRKInstructions = (md: string = '') => {

    (md != '' ? Process.findModuleByName(md)! : Process.mainModule)
        .enumerateSections()
        .forEach(item => {
            if (item.name == '__text') {
                logw(`\n${item.address} -> ${item.name} ${ptr(item.size)}\n`)
                Memory.scanSync(item.address, item.size, "20 00 20 D4").forEach((item, index) => {
                    logd(`[${index}] ->\t${item.address.sub(Process.mainModule.base)} | ${DebugSymbol.fromAddress(item.address)}`)
                    const currentIns = Instruction.parse(item.address)
                    logd(`[${index}] \t${currentIns.address} ${currentIns}`)
                })
                newLine()
            }
        })
}

var registerFlag = false
const regExceptionHandle = () => {
    if (registerFlag) return
    registerFlag = true
    Process.setExceptionHandler((callback) => {
        if (targetPointers.includes(callback.address)) {
            loge(`Got Ins Err -> ${callback.address}`)
            let ins_value = callback.address.readU32()
            callback.address.writeU32(ptr(ins_value).xor(ins_value).toUInt32())
            return true
        }
        return false
    })
}

globalThis.nopSysCall = (md: string = '', nopAll: boolean = false) => {
    findSvcInstructions(md)
    targetPointers.forEach(item => {
        Memory.patchCode(item, 0x4, (addr) => {
            const lastIns = Instruction.parse(addr.sub(0x4))
            const opCode = Number((lastIns as Arm64Instruction).operands.find(i => i.type == "imm")?.value)
            if (Process.arch == "arm64") {
                if (opCode == SYSCALL.SYS_exit || opCode == SYSCALL.SYS_ptrace) {
                    new Arm64Writer(addr).putNop()
                } else if (nopAll) new Arm64Writer(addr).putNop()
            } else {
                Interceptor.attach(lastIns.address, {
                    onEnter(args) {
                        logd(`Called SVC -> ${SYSCALL[opCode]} @ ${addr}`)
                        new Arm64Writer(addr).putNop()
                    }
                })
                
            }
        })
    })
}

globalThis.modTargets = () => {
    regExceptionHandle()
    logw(`targetPointers -> ${targetPointers.length}`)
    targetPointers.forEach(item => {
        Memory.patchCode(item, 0x4, (ins) => {
            let ins_value = ins.readU32()
            ins.writeU32(ptr(ins_value).xor(ins_value).toUInt32())
        })
    })
}

declare global {
    var findSvcInstructions: (md?: string) => void
    var findBRKInstructions: (md?: string) => void
    var modTargets: () => void
    var nopSysCall: (md?: string, nopAll?: boolean) => void
}

// https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS13.0.sdk/usr/include/sys/syscall.h
export enum SYSCALL {
    SYS_syscall = 0,
    SYS_exit = 1,
    SYS_fork = 2,
    SYS_read = 3,
    SYS_write = 4,
    SYS_open = 5,
    SYS_close = 6,
    SYS_wait4 = 7,
    // 8 is old creat
    SYS_link = 9,
    SYS_unlink = 10,
    // 11 is old execv
    SYS_chdir = 12,
    SYS_fchdir = 13,
    SYS_mknod = 14,
    SYS_chmod = 15,
    SYS_chown = 16,
    // 17 is old break
    SYS_getfsstat = 18,
    // 19 is old lseek
    SYS_getpid = 20,
    // 21 is old mount
    // 22 is old umount
    SYS_setuid = 23,
    SYS_getuid = 24,
    SYS_geteuid = 25,
    SYS_ptrace = 26,
    SYS_recvmsg = 27,
    SYS_sendmsg = 28,
    SYS_recvfrom = 29,
    SYS_accept = 30,
    SYS_getpeername = 31,
    SYS_getsockname = 32,
    SYS_access = 33,
    SYS_chflags = 34,
    SYS_fchflags = 35,
    SYS_sync = 36,
    SYS_kill = 37,
    // 38 is old stat
    SYS_getppid = 39,
    // 40 is old lstat
    SYS_dup = 41,
    SYS_pipe = 42,
    SYS_getegid = 43,
    // 44 is old profil
    // 45 is old ktrace
    SYS_sigaction = 46,
    SYS_getgid = 47,
    SYS_sigprocmask = 48,
    SYS_getlogin = 49,
    SYS_setlogin = 50,
    SYS_acct = 51,
    SYS_sigpending = 52,
    SYS_sigaltstack = 53,
    SYS_ioctl = 54,
    SYS_reboot = 55,
    SYS_revoke = 56,
    SYS_symlink = 57,
    SYS_readlink = 58,
    SYS_execve = 59,
    SYS_umask = 60,
    SYS_chroot = 61,
    // 62 is old fstat
    SYS_invalid = 63,
    // 64 is old getpagesize
    SYS_msync = 65,
    SYS_vfork = 66,
    // 67 is old vread
    // 68 is old vwrite
    // 69 is old sbrk
    // 70 is old sstk
    // 71 is old mmap
    // 72 is old vadvise
    SYS_munmap = 73,
    SYS_mprotect = 74,
    SYS_madvise = 75,
    // 76 is old vhangup
    // 77 is old vlimit
    SYS_mincore = 78,
    SYS_getgroups = 79,
    SYS_setgroups = 80,
    SYS_getpgrp = 81,
    SYS_setpgid = 82,
    SYS_setitimer = 83,
    // 84 is old wait
    SYS_swapon = 85,
    SYS_getitimer = 86,
    // 87 is old gethostname
    // 88 is old sethostname
    SYS_getdtablesize = 89,
    SYS_dup2 = 90,
    // 91 is old getdopt
    SYS_fcntl = 92,
    SYS_select = 93,
    // 94 is old setdopt
    SYS_fsync = 95,
    SYS_setpriority = 96,
    SYS_socket = 97,
    SYS_connect = 98,
    // 99 is old accept
    SYS_getpriority = 100,
    // 101 is old send
    // 102 is old recv
    // 103 is old sigreturn
    SYS_bind = 104,
    SYS_setsockopt = 105,
    SYS_listen = 106,
    // 107 is old vtimes
    // 108 is old sigvec
    // 109 is old sigblock
    // 110 is old sigsetmask
    SYS_sigsuspend = 111,
    // 112 is old sigstack
    // 113 is old recvmsg
    // 114 is old sendmsg
    // 115 is old vtrace
    SYS_gettimeofday = 116,
    SYS_getrusage = 117,
    SYS_getsockopt = 118,
    // 119 is old resuba
    SYS_readv = 120,
    SYS_writev = 121,
    SYS_settimeofday = 122,
    SYS_fchown = 123,
    SYS_fchmod = 124,
    // 125 is old recvfrom
    SYS_setreuid = 126,
    SYS_setregid = 127,
    SYS_rename = 128,
    // 129 is old truncate
    // 130 is old ftruncate
    SYS_flock = 131,
    SYS_mkfifo = 132,
    SYS_sendto = 133,
    SYS_shutdown = 134,
    SYS_socketpair = 135,
    SYS_mkdir = 136,
    SYS_rmdir = 137,
    SYS_utimes = 138,
    SYS_futimes = 139,
    SYS_adjtime = 140,
    // 141 is old getpeername
    SYS_gethostuuid = 142,
    // 143 is old sethostid
    // 144 is old getrlimit
    // 145 is old setrlimit
    // 146 is old killpg
    SYS_setsid = 147,
    // 148 is old setquota
    // 149 is old qquota
    // 150 is old getsockname
    SYS_getpgid = 151,
    SYS_setprivexec = 152,
    SYS_pread = 153,
    SYS_pwrite = 154,
    SYS_nfssvc = 155,
    // 156 is old getdirentries
    SYS_statfs = 157,
    SYS_fstatfs = 158,
    SYS_unmount = 159,
    // 160 is old async_daemon
    SYS_getfh = 161,
    // 162 is old getdomainname
    // 163 is old setdomainname
    // 164 is unused
    SYS_quotactl = 165,
    // 166 is old exportfs
    SYS_mount = 167,
    // 168 is old ustat
    SYS_csops = 169,
    SYS_csops_audittoken = 170,
    // 171 is old wait3
    // 172 is old rpause
    SYS_waitid = 173,
    // 174 is old getdents
    // 175 is old gc_control
    // 176 is old add_profil
    SYS_kdebug_typefilter = 177,
    SYS_kdebug_trace_string = 178,
    SYS_kdebug_trace64 = 179,
    SYS_kdebug_trace = 180,
    SYS_setgid = 181,
    SYS_setegid = 182,
    SYS_seteuid = 183,
    SYS_sigreturn = 184,
    // 185 is old chud
    SYS_thread_selfcounts = 186,
    SYS_fdatasync = 187,
    SYS_stat = 188,
    SYS_fstat = 189,
    SYS_lstat = 190,
    SYS_pathconf = 191,
    SYS_fpathconf = 192,
    // 193 is old getfsstat
    SYS_getrlimit = 194,
    SYS_setrlimit = 195,
    SYS_getdirentries = 196,
    SYS_mmap = 197,
    // 198 is old __syscall
    SYS_lseek = 199,
    SYS_truncate = 200,
    SYS_ftruncate = 201,
    SYS_sysctl = 202,
    SYS_mlock = 203,
    SYS_munlock = 204,
    SYS_undelete = 205,
    // 206 is old ATsocket
    // 207 is old ATgetmsg
    // 208 is old ATputmsg
    // 209 is old ATsndreq
    // 210 is old ATsndrsp
    // 211 is old ATgetreq
    // 212 is old ATgetrsp
    // 213 is reserved for AppleTalk
    // 214 is unused
    // 215 is unused
    SYS_open_dprotected_np = 216,
    SYS_fsgetpath_ext = 217,
    // 218 is old lstatv
    // 219 is old fstatv
    SYS_getattrlist = 220,
    SYS_setattrlist = 221,
    SYS_getdirentriesattr = 222,
    SYS_exchangedata = 223,
    // 224 is old checkuseraccess or fsgetpath
    SYS_searchfs = 225,
    SYS_delete = 226,
    SYS_copyfile = 227,
    SYS_fgetattrlist = 228,
    SYS_fsetattrlist = 229,
    SYS_poll = 230,
    SYS_watchevent = 231,
    SYS_waitevent = 232,
    SYS_modwatch = 233,
    SYS_getxattr = 234,
    SYS_fgetxattr = 235,
    SYS_setxattr = 236,
    SYS_fsetxattr = 237,
    SYS_removexattr = 238,
    SYS_fremovexattr = 239,
    SYS_listxattr = 240,
    SYS_flistxattr = 241,
    SYS_fsctl = 242,
    SYS_initgroups = 243,
    SYS_posix_spawn = 244,
    SYS_ffsctl = 245,
    // 246 is unused
    SYS_nfsclnt = 247,
    SYS_fhopen = 248,
    // 249 is unused
    SYS_minherit = 250,
    SYS_semsys = 251,
    SYS_msgsys = 252,
    SYS_shmsys = 253,
    SYS_semctl = 254,
    SYS_semget = 255,
    SYS_semop = 256,
    // 257 is old semconfig
    SYS_msgctl = 258,
    SYS_msgget = 259,
    SYS_msgsnd = 260,
    SYS_msgrcv = 261,
    SYS_shmat = 262,
    SYS_shmctl = 263,
    SYS_shmdt = 264,
    SYS_shmget = 265,
    SYS_shm_open = 266,
    SYS_shm_unlink = 267,
    SYS_sem_open = 268,
    SYS_sem_close = 269,
    SYS_sem_unlink = 270,
    SYS_sem_wait = 271,
    SYS_sem_trywait = 272,
    SYS_sem_post = 273,
    SYS_sysctlbyname = 274,
    // 275 is old sem_init
    // 276 is old sem_destroy
    SYS_open_extended = 277,
    SYS_umask_extended = 278,
    SYS_stat_extended = 279,
    SYS_lstat_extended = 280,
    SYS_fstat_extended = 281,
    SYS_chmod_extended = 282,
    SYS_fchmod_extended = 283,
    SYS_access_extended = 284,
    SYS_settid = 285,
    SYS_gettid = 286,
    SYS_setsgroups = 287,
    SYS_getsgroups = 288,
    SYS_setwgroups = 289,
    SYS_getwgroups = 290,
    SYS_mkfifo_extended = 291,
    SYS_mkdir_extended = 292,
    SYS_identitysvc = 293,
    SYS_shared_region_check_np = 294,
    // 295 is old shared_region_map_np
    SYS_vm_pressure_monitor = 296,
    SYS_psynch_rw_longrdlock = 297,
    SYS_psynch_rw_yieldwrlock = 298,
    SYS_psynch_rw_downgrade = 299,
    SYS_psynch_rw_upgrade = 300,
    SYS_psynch_mutexwait = 301,
    SYS_psynch_mutexdrop = 302,
    SYS_psynch_cvbroad = 303,
    SYS_psynch_cvsignal = 304,
    SYS_psynch_cvwait = 305,
    SYS_psynch_rw_rdlock = 306,
    SYS_psynch_rw_wrlock = 307,
    SYS_psynch_rw_unlock = 308,
    SYS_psynch_rw_unlock2 = 309,
    SYS_getsid = 310,
    SYS_settid_with_pid = 311,
    SYS_psynch_cvclrprepost = 312,
    SYS_aio_fsync = 313,
    SYS_aio_return = 314,
    SYS_aio_suspend = 315,
    SYS_aio_cancel = 316,
    SYS_aio_error = 317,
    SYS_aio_read = 318,
    SYS_aio_write = 319,
    SYS_lio_listio = 320,
    // 321 is old __pthread_cond_wait
    SYS_iopolicysys = 322,
    SYS_process_policy = 323,
    SYS_mlockall = 324,
    SYS_munlockall = 325,
    // 326 is unused
    SYS_issetugid = 327,
    SYS___pthread_kill = 328,
    SYS___pthread_sigmask = 329,
    SYS___sigwait = 330,
    SYS___disable_threadsignal = 331,
    SYS___pthread_markcancel = 332,
    SYS___pthread_canceled = 333,
    SYS___semwait_signal = 334,
    // 335 is old utrace
    SYS_proc_info = 336,
    SYS_sendfile = 337,
    SYS_stat64 = 338,
    SYS_fstat64 = 339,
    SYS_lstat64 = 340,
    SYS_stat64_extended = 341,
    SYS_lstat64_extended = 342,
    SYS_fstat64_extended = 343,
    SYS_getdirentries64 = 344,
    SYS_statfs64 = 345,
    SYS_fstatfs64 = 346,
    SYS_getfsstat64 = 347,
    SYS___pthread_chdir = 348,
    SYS___pthread_fchdir = 349,
    SYS_audit = 350,
    SYS_auditon = 351,
    // 352 is unused
    SYS_getauid = 353,
    SYS_setauid = 354,
    // 355 is old getaudit
    // 356 is old setaudit
    SYS_getaudit_addr = 357,
    SYS_setaudit_addr = 358,
    SYS_auditctl = 359,
    SYS_bsdthread_create = 360,
    SYS_bsdthread_terminate = 361,
    SYS_kqueue = 362,
    SYS_kevent = 363,
    SYS_lchown = 364,
    // 365 is old stack_snapshot
    SYS_bsdthread_register = 366,
    SYS_workq_open = 367,
    SYS_workq_kernreturn = 368,
    SYS_kevent64 = 369,
    SYS___old_semwait_signal = 370,
    SYS___old_semwait_signal_nocancel = 371,
    SYS_thread_selfid = 372,
    SYS_ledger = 373,
    SYS_kevent_qos = 374,
    SYS_kevent_id = 375,
    // 376 is unused
    // 377 is unused
    // 378 is unused
    // 379 is unused
    SYS___mac_execve = 380,
    SYS___mac_syscall = 381,
    SYS___mac_get_file = 382,
    SYS___mac_set_file = 383,
    SYS___mac_get_link = 384,
    SYS___mac_set_link = 385,
    SYS___mac_get_proc = 386,
    SYS___mac_set_proc = 387,
    SYS___mac_get_fd = 388,
    SYS___mac_set_fd = 389,
    SYS___mac_get_pid = 390,
    // 391 is unused
    // 392 is unused
    // 393 is unused
    SYS_pselect = 394,
    SYS_pselect_nocancel = 395,
    SYS_read_nocancel = 396,
    SYS_write_nocancel = 397,
    SYS_open_nocancel = 398,
    SYS_close_nocancel = 399,
    SYS_wait4_nocancel = 400,
    SYS_recvmsg_nocancel = 401,
    SYS_sendmsg_nocancel = 402,
    SYS_recvfrom_nocancel = 403,
    SYS_accept_nocancel = 404,
    SYS_msync_nocancel = 405,
    SYS_fcntl_nocancel = 406,
    SYS_select_nocancel = 407,
    SYS_fsync_nocancel = 408,
    SYS_connect_nocancel = 409,
    SYS_sigsuspend_nocancel = 410,
    SYS_readv_nocancel = 411,
    SYS_writev_nocancel = 412,
    SYS_sendto_nocancel = 413,
    SYS_pread_nocancel = 414,
    SYS_pwrite_nocancel = 415,
    SYS_waitid_nocancel = 416,
    SYS_poll_nocancel = 417,
    SYS_msgsnd_nocancel = 418,
    SYS_msgrcv_nocancel = 419,
    SYS_sem_wait_nocancel = 420,
    SYS_aio_suspend_nocancel = 421,
    SYS___sigwait_nocancel = 422,
    SYS___semwait_signal_nocancel = 423,
    SYS___mac_mount = 424,
    SYS___mac_get_mount = 425,
    SYS___mac_getfsstat = 426,
    SYS_fsgetpath = 427,
    SYS_audit_session_self = 428,
    SYS_audit_session_join = 429,
    SYS_fileport_makeport = 430,
    SYS_fileport_makefd = 431,
    SYS_audit_session_port = 432,
    SYS_pid_suspend = 433,
    SYS_pid_resume = 434,
    SYS_pid_hibernate = 435,
    SYS_pid_shutdown_sockets = 436,
    // 437 is old shared_region_slide_np
    SYS_shared_region_map_and_slide_np = 438,
    SYS_kas_info = 439,
    SYS_memorystatus_control = 440,
    SYS_guarded_open_np = 441,
    SYS_guarded_close_np = 442,
    SYS_guarded_kqueue_np = 443,
    SYS_change_fdguard_np = 444,
    SYS_usrctl = 445,
    SYS_proc_rlimit_control = 446,
    SYS_connectx = 447,
    SYS_disconnectx = 448,
    SYS_peeloff = 449,
    SYS_socket_delegate = 450,
    SYS_telemetry = 451,
    SYS_proc_uuid_policy = 452,
    SYS_memorystatus_get_level = 453,
    SYS_system_override = 454,
    SYS_vfs_purge = 455,
    SYS_sfi_ctl = 456,
    SYS_sfi_pidctl = 457,
    SYS_coalition = 458,
    SYS_coalition_info = 459,
    SYS_necp_match_policy = 460,
    SYS_getattrlistbulk = 461,
    SYS_clonefileat = 462,
    SYS_openat = 463,
    SYS_openat_nocancel = 464,
    SYS_renameat = 465,
    SYS_faccessat = 466,
    SYS_fchmodat = 467,
    SYS_fchownat = 468,
    SYS_fstatat = 469,
    SYS_fstatat64 = 470,
    SYS_linkat = 471,
    SYS_unlinkat = 472,
    SYS_readlinkat = 473,
    SYS_symlinkat = 474,
    SYS_mkdirat = 475,
    SYS_getattrlistat = 476,
    SYS_proc_trace_log = 477,
    SYS_bsdthread_ctl = 478,
    SYS_openbyid_np = 479,
    SYS_recvmsg_x = 480,
    SYS_sendmsg_x = 481,
    SYS_thread_selfusage = 482,
    SYS_csrctl = 483,
    SYS_guarded_open_dprotected_np = 484,
    SYS_guarded_write_np = 485,
    SYS_guarded_pwrite_np = 486,
    SYS_guarded_writev_np = 487,
    SYS_renameatx_np = 488,
    SYS_mremap_encrypted = 489,
    SYS_netagent_trigger = 490,
    SYS_stack_snapshot_with_config = 491,
    SYS_microstackshot = 492,
    SYS_grab_pgo_data = 493,
    SYS_persona = 494,
    // 495-498 are unused
    SYS_work_interval_ctl = 499,
    SYS_getentropy = 500,
    SYS_necp_open = 501,
    SYS_necp_client_action = 502,
    SYS___nexus_open = 503,
    SYS___nexus_register = 504,
    SYS___nexus_deregister = 505,
    SYS___nexus_create = 506,
    SYS___nexus_destroy = 507,
    SYS___nexus_get_opt = 508,
    SYS___nexus_set_opt = 509,
    SYS___channel_open = 510,
    SYS___channel_get_info = 511,
    SYS___channel_sync = 512,
    SYS___channel_get_opt = 513,
    SYS___channel_set_opt = 514,
    SYS_ulock_wait = 515,
    SYS_ulock_wake = 516,
    SYS_fclonefileat = 517,
    SYS_fs_snapshot = 518,
    // 519 is unused
    SYS_terminate_with_payload = 520,
    SYS_abort_with_payload = 521,
    SYS_necp_session_open = 522,
    SYS_necp_session_action = 523,
    SYS_setattrlistat = 524,
    SYS_net_qos_guideline = 525,
    SYS_fmount = 526,
    SYS_ntp_adjtime = 527,
    SYS_ntp_gettime = 528,
    SYS_os_fault_with_payload = 529,
    SYS_kqueue_workloop_ctl = 530,
    SYS___mach_bridge_remote_time = 531,
    SYS_coalition_ledger = 532,
    SYS_log_data = 533,
    SYS_memorystatus_available_memory = 534,
    SYS_MAXSYSCALL = 535
}

// #include <machine/signal.h>     /* sigcontext; codes for SIGILL, SIGFPE */

// #define SIGHUP  1       /* hangup */
// #define SIGINT  2       /* interrupt */
// #define SIGQUIT 3       /* quit */
// #define SIGILL  4       /* illegal instruction (not reset when caught) */
// #define SIGTRAP 5       /* trace trap (not reset when caught) */
// #define SIGABRT 6       /* abort() */
// #if  (defined(_POSIX_C_SOURCE) && !defined(_DARWIN_C_SOURCE))
// #define SIGPOLL 7       /* pollable event ([XSR] generated, not supported) */
// #else   /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
// #define SIGIOT  SIGABRT /* compatibility */
// #define SIGEMT  7       /* EMT instruction */
// #endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
// #define SIGFPE  8       /* floating point exception */
// #define SIGKILL 9       /* kill (cannot be caught or ignored) */
// #define SIGBUS  10      /* bus error */
// #define SIGSEGV 11      /* segmentation violation */
// #define SIGSYS  12      /* bad argument to system call */
// #define SIGPIPE 13      /* write on a pipe with no one to read it */
// #define SIGALRM 14      /* alarm clock */
// #define SIGTERM 15      /* software termination signal from kill */
// #define SIGURG  16      /* urgent condition on IO channel */
// #define SIGSTOP 17      /* sendable stop signal not from tty */
// #define SIGTSTP 18      /* stop signal from tty */
// #define SIGCONT 19      /* continue a stopped process */
// #define SIGCHLD 20      /* to parent on child stop or exit */
// #define SIGTTIN 21      /* to readers pgrp upon background tty read */
// #define SIGTTOU 22      /* like TTIN for output if (tp->t_local&LTOSTOP) */
// #if  (!defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE))
// #define SIGIO   23      /* input/output possible signal */
// #endif
// #define SIGXCPU 24      /* exceeded CPU time limit */
// #define SIGXFSZ 25      /* exceeded file size limit */
// #define SIGVTALRM 26    /* virtual time alarm */
// #define SIGPROF 27      /* profiling time alarm */
// #if  (!defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE))
// #define SIGWINCH 28     /* window size changes */
// #define SIGINFO 29      /* information request */
// #endif
// #define SIGUSR1 30      /* user defined signal 1 */
// #define SIGUSR2 31      /* user defined signal 2 */

// #if defined(_ANSI_SOURCE) || __DARWIN_UNIX03 || defined(__cplusplus)
// /*
//  * Language spec sez we must list exactly one parameter, even though we
//  * actually supply three.  Ugh!
//  * SIG_HOLD is chosen to avoid KERN_SIG_* values in <sys/signalvar.h>
//  */
// #define SIG_DFL         (void (*)(int))0
// #define SIG_IGN         (void (*)(int))1
// #define SIG_HOLD        (void (*)(int))5
// #define SIG_ERR         ((void (*)(int))-1)
// #else
// /* DO NOT REMOVE THE COMMENTED OUT int: fixincludes needs to see them */
// #define SIG_DFL         (void (*)( /*int*/ ))0
// #define SIG_IGN         (void (*)( /*int*/ ))1
// #define SIG_HOLD        (void (*)( /*int*/ ))5
// #define SIG_ERR         ((void (*)( /*int*/ ))-1)
// #endif
export enum SIGNAL {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGEMT = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGBUS = 10,
    SIGSEGV = 11,
    SIGSYS = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGURG = 16,
    SIGSTOP = 17,
    SIGTSTP = 18,
    SIGCONT = 19,
    SIGCHLD = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGPOLL = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    SIGINFO = 29,
    SIGUSR1 = 30,
    SIGUSR2 = 31,
    SIG_BLOCK = 0,
    SIG_UNBLOCK = 1,
}