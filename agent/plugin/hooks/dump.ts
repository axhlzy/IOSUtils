import { AnyNsRecord } from "dns";

Module.ensureInitialized('Foundation');

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str: string) {
    return Memory.allocUtf8String(str);
}

function putStr(addr: NativePointer, str: string) {
    addr.writeUtf8String(str)
}

function getByteArr(addr: NativePointer, l: any) {
    addr.writeByteArray(l);
}

function getU8(addr: NativePointer) {
    return addr.readU8();
}

function putU8(addr: NativePointer, n: number) {
    addr.writeU8(n);
}

function getU16(addr: NativePointer) {
    return addr.readU16();
}

function putU16(addr: NativePointer, n: number) {
    addr.writeU16(n);
}

function getU32(addr: NativePointer) {
    return addr.readU32();
}

function putU32(addr: NativePointer, n: number) {
    addr.writeU32(n);
}

function getU64(addr: NativePointer) {
    return addr.readU64();
}

function putU64(addr: NativePointer, n: number) {
    addr.writeU64(n);
}

function getPt(addr: NativePointer) {
    return addr.readPointer();
}

function putPt(addr: NativePointer, n: NativePointer) {
    addr.writePointer(n);
}

function malloc(size: number) {
    return Memory.alloc(size);
}

function getExportFunction(type: string, name: string, ret: any, args: any[]): Function | undefined {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        // return null;
        return () => { };
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                // return null;
                return () => { };
            }
            return funclet;
        } else if (type === "d") {
            var datalet = nptr.readPointer()
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                // return null;
                return () => { };
            }
            return datalet as unknown as Function;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var remove = getExportFunction("f", "remove", "int", ["pointer"]);
var access = getExportFunction("f", "access", "int", ["pointer", "int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);


function loadAllDynamicLibrary(app_path: { stringByAppendingPathComponent_: (arg0: any) => any; }) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    errorPtr.writePointer(NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success. ");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") ||
            file_name.hasSuffix_(".momd") ||
            file_name.hasSuffix_(".strings") ||
            file_name.hasSuffix_(".appex") ||
            file_name.hasSuffix_(".app") ||
            file_name.hasSuffix_(".lproj") ||
            file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            isDirPtr.writePointer(NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (isDirPtr.readPointer().toInt32() == 1) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
                            break;
                        }
                    }

                    if (!is_loaded) {
                        if (dlopen!(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function open(pathname: string | NativePointer, flags: any, mode: any) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open!(pathname, flags, mode);
}

function getDocumentDir() {
    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = (NSSearchPathForDirectoriesInDomains as unknown as Function)(NSDocumentDirectory, NSUserDomainMask, 1);
    return new ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function swap32(value: any) {
    value = pad(value.toString(16), 8)
    var result = "";
    for (var i = 0; i < value.length; i = i + 2) {
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result, 16)
}

function pad(str: string, n: number) {
    return Array(n - str.length + 1).join("0") + str;
}

var modules: any = null;
function getAllAppModules() {
    modules = new Array();
    var tmpmods = Process.enumerateModules();
    for (var i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

export function dumpAllMd() {
    modules = getAllAppModules();
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    // start dump
    modules = getAllAppModules();
    for (var i = 0; i < modules.length; i++) {
        console.log("start dump " + modules[i].path);
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path });
    }
}

export function dumpModule(name: string) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + newmodname + ".fid";
    var oldmodpath = modules[i].path;


    if (!access!(allocStr(newmodpath), 0)) {
        remove!(allocStr(newmodpath));
    }

    var fmodule = open!(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = open!(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.log("Cannot open file" + newmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);

    read!(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if (cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype) {
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if (fileoffset == 0 || filesize == 0)
            return;

        lseek!(fmodule, 0, SEEK_SET);
        lseek!(foldmodule, fileoffset, SEEK_SET);
        for (var i = 0; i < filesize / BUFSIZE; i++) {
            read!(foldmodule, buffer, BUFSIZE);
            write!(fmodule, buffer, BUFSIZE);
        }
        if (filesize % BUFSIZE) {
            read!(foldmodule, buffer, filesize % BUFSIZE);
            write!(fmodule, buffer, filesize % BUFSIZE);
        }
    } else {
        var readLen = 0;
        lseek!(foldmodule, 0, SEEK_SET);
        lseek!(fmodule, 0, SEEK_SET);
        while (readLen = read!(foldmodule, buffer, BUFSIZE)) {
            write!(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek!(fmodule, offset_cryptid, SEEK_SET);
        write!(fmodule, tpbuf, 4);
        lseek!(fmodule, crypt_off, SEEK_SET);
        write!(fmodule, modbase.add(crypt_off), crypt_size);
    }

    close!(fmodule);
    close!(foldmodule);
    return newmodpath
}

declare global {
    var dumpModule: (mdName:string) => void
    var dumpAllMd: () => void
}

export { }

globalThis.dumpModule = dumpModule
globalThis.dumpAllMd = dumpAllMd
