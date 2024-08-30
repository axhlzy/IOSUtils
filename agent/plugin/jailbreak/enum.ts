// 
// /*
//  * CTL_KERN identifiers
//  */
// #define KERN_OSTYPE              1      /* string: system version */
// #define KERN_OSRELEASE           2      /* string: system release */
// #define KERN_OSREV               3      /* int: system revision */
// #define KERN_VERSION             4      /* string: compile time info */
// #define KERN_MAXVNODES           5      /* int: max vnodes */
// #define KERN_MAXPROC             6      /* int: max processes */
// #define KERN_MAXFILES            7      /* int: max open files */
// #define KERN_ARGMAX              8      /* int: max arguments to exec */
// #define KERN_SECURELVL           9      /* int: system security level */
// #define KERN_HOSTNAME           10      /* string: hostname */
// #define KERN_HOSTID             11      /* int: host identifier */
// #define KERN_CLOCKRATE          12      /* struct: struct clockrate */
// #define KERN_VNODE              13      /* struct: vnode structures */
// #define KERN_PROC               14      /* struct: process entries */
// #define KERN_FILE               15      /* struct: file entries */
// #define KERN_PROF               16      /* node: kernel profiling info */
// #define KERN_POSIX1             17      /* int: POSIX.1 version */
// #define KERN_NGROUPS            18      /* int: # of supplemental group ids */
// #define KERN_JOB_CONTROL        19      /* int: is job control available */
// #define KERN_SAVED_IDS          20      /* int: saved set-user/group-ID */
// #define KERN_BOOTTIME           21      /* struct: time kernel was booted */
// #define KERN_NISDOMAINNAME      22      /* string: YP domain name */
// #define KERN_DOMAINNAME         KERN_NISDOMAINNAME
// #define KERN_MAXPARTITIONS      23      /* int: number of partitions/disk */
// #define KERN_KDEBUG             24      /* int: kernel trace points */
// #define KERN_UPDATEINTERVAL     25      /* int: update process sleep time */
// #define KERN_OSRELDATE          26      /* int: OS release date */
// #define KERN_NTP_PLL            27      /* node: NTP PLL control */
// #define KERN_BOOTFILE           28      /* string: name of booted kernel */
// #define KERN_MAXFILESPERPROC    29      /* int: max open files per proc */
// #define KERN_MAXPROCPERUID      30      /* int: max processes per uid */
// #define KERN_DUMPDEV            31      /* dev_t: device to dump on */
// #define KERN_IPC                32      /* node: anything related to IPC */
// #define KERN_DUMMY              33      /* unused */
// #define KERN_PS_STRINGS 34      /* int: address of PS_STRINGS */
// #define KERN_USRSTACK32 35      /* int: address of USRSTACK */
// #define KERN_LOGSIGEXIT 36      /* int: do we log sigexit procs? */
// #define KERN_SYMFILE            37      /* string: kernel symbol filename */
// #define KERN_PROCARGS           38
// /* 39 was KERN_PCSAMPLES... now obsolete */
// #define KERN_NETBOOT            40      /* int: are we netbooted? 1=yes,0=no */
// /* 41 was KERN_PANICINFO : panic UI information (deprecated) */
// #define KERN_SYSV               42      /* node: System V IPC information */
// #define KERN_AFFINITY           43      /* xxx */
// #define KERN_TRANSLATE          44      /* xxx */
// #define KERN_CLASSIC            KERN_TRANSLATE  /* XXX backwards compat */
// #define KERN_EXEC               45      /* xxx */
// #define KERN_CLASSICHANDLER     KERN_EXEC /* XXX backwards compatibility */
// #define KERN_AIOMAX             46      /* int: max aio requests */
// #define KERN_AIOPROCMAX         47      /* int: max aio requests per process */
// #define KERN_AIOTHREADS         48      /* int: max aio worker threads */
// #ifdef __APPLE_API_UNSTABLE
// #define KERN_PROCARGS2          49
// #endif /* __APPLE_API_UNSTABLE */
// #define KERN_COREFILE           50      /* string: corefile format string */
// #define KERN_COREDUMP           51      /* int: whether to coredump at all */
// #define KERN_SUGID_COREDUMP     52      /* int: whether to dump SUGID cores */
// #define KERN_PROCDELAYTERM      53      /* int: set/reset current proc for delayed termination during shutdown */
// #define KERN_SHREG_PRIVATIZABLE 54      /* int: can shared regions be privatized ? */
// /* 55 was KERN_PROC_LOW_PRI_IO... now deprecated */
// #define KERN_LOW_PRI_WINDOW     56      /* int: set/reset throttle window - milliseconds */
// #define KERN_LOW_PRI_DELAY      57      /* int: set/reset throttle delay - milliseconds */
// #define KERN_POSIX              58      /* node: posix tunables */
// #define KERN_USRSTACK64         59      /* LP64 user stack query */
// #define KERN_NX_PROTECTION      60      /* int: whether no-execute protection is enabled */
// #define KERN_TFP                61      /* Task for pid settings */
// #define KERN_PROCNAME           62      /* setup process program  name(2*MAXCOMLEN) */
// #define KERN_THALTSTACK         63      /* for compat with older x86 and does nothing */
// #define KERN_SPECULATIVE_READS  64      /* int: whether speculative reads are disabled */
// #define KERN_OSVERSION          65      /* for build number i.e. 9A127 */
// #define KERN_SAFEBOOT           66      /* are we booted safe? */
// /*	67 was KERN_LCTX (login context) */
// #define KERN_RAGEVNODE          68
// #define KERN_TTY                69      /* node: tty settings */
// #define KERN_CHECKOPENEVT       70      /* spi: check the VOPENEVT flag on vnodes at open time */
// #define KERN_THREADNAME         71      /* set/get thread name */
// #define KERN_MAXID              72      /* number of valid kern ids */

export enum CTL_KERN {
    KERN_SECURELVL = 9,
    KERN_HOSTNAME = 10,
    KERN_HOSTID = 11,
    KERN_CLOCKRATE = 12,
    KERN_VNODE = 13,
    KERN_PROC = 14,
    KERN_FILE = 15,
    KERN_PROF = 16,
    KERN_POSIX1 = 17,
    KERN_NGROUPS = 18,
    //...
}


// 第一个name数组可以包含以下
// #define CTL_UNSPEC      0               /* unused */
// #define CTL_KERN        1               /* "high kernel": proc, limits */
// #define CTL_VM          2               /* virtual memory */
// #define CTL_VFS         3               /* file system, mount type is next */
// #define CTL_NET         4               /* network, see socket.h */
// #define CTL_DEBUG       5               /* debugging parameters */
// #define CTL_HW          6               /* generic cpu/io */
// #define CTL_MACHDEP     7               /* machine dependent */
// #define CTL_USER        8               /* user-level */
// #define CTL_MAXID       9               /* number of valid top-level ids */

export enum CTLT_YPE{
    CTL_UNSPEC = 0,
    CTL_KERN = 1,
    CTL_VM = 2,
    CTL_VFS = 3,
    CTL_NET = 4,
    CTL_DEBUG = 5,
    CTL_HW = 6,
    CTL_MACHDEP = 7,
    CTL_USER = 8,
    CTL_MAXID = 9
}
