const test_NEHASDK = () => {

    // // -[NEHASDK startWithSettings:]
    Interceptor.replace(ObjC.classes["NEHASDK"]["- startWithSettings:"].implementation, new NativeCallback(() => {
        logw(`\nCalled NEHASDK startWithSettings:`)
    }, "void", ["pointer", "pointer"]))

}

// -[NIMSDK registerWithOption:]
// Interceptor.replace(ObjC.classes["NIMSDK"]["- registerWithOption:"].implementation, new NativeCallback(() => {
//     logw(`\nCalled NIMSDK!-[NEHASDK startWithSettings:]`)
// }, "void", ["pointer", "pointer"]))

// NIMSDK!-[NIMPathManager createDirIfNotExists:]
// Interceptor.attach(ObjC.classes["NIMPathManager"]["- createDirIfNotExists:"].implementation, {
//     onEnter(args) {
//         const instance = new ObjC.Object(args[0])
//         logw(`\nCalled NIMSDK!-[NIMPathManager createDirIfNotExists:] ${instance}, ${asOcObjtoString(args[2])}`)
//     }
// })