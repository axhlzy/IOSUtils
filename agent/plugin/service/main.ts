

setImmediate(() => {

    return
    B_NSLOG()

    // typedef int kern_return_t
    type kern_return_t = number
    const addr_IOObjectConformsTo = DebugSymbol.fromName("IOObjectConformsTo").address
    const func_IOObjectConformsTo = new NativeFunction(addr_IOObjectConformsTo, 'int', ['pointer', 'pointer'])

    const addr_IORegistryEntryGetName = Module.getExportByName(null, "IORegistryEntryGetName")

    // KERN_SUCCESS 0
    const KERN_SUCCESS: number = 0

    const cstr_IOWatchdog = allocCString("IOWatchdog")

    let gIOWatchdogConnection: NativePointer = NULL

    // kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect)
    const addr_IOServiceOpen = DebugSymbol.fromName("IOServiceOpen").address
    Interceptor.replace(addr_IOServiceOpen, new NativeCallback((service, owningTask, type, connect) => {
        const originalFunction = new NativeFunction(
            addr_IOServiceOpen,
            'int',
            ['pointer', 'pointer', 'uint', 'pointer']
        )

        const result = originalFunction(service, owningTask, type, connect)
        const nameBuffer = Memory.alloc(512)
        const length = 512

        const IORegistryEntryGetName = new NativeFunction(
            addr_IORegistryEntryGetName,
            'int',
            ['pointer', 'pointer', 'uint32']
        )

        if (IORegistryEntryGetName(service, nameBuffer, length) === KERN_SUCCESS) {
            const serviceName = nameBuffer.readUtf8String()
            logd(`Service Name: ${serviceName}`)
        } else {
            loge("Failed to get the service name")
        }


        logd(`Called IOServiceOpen ${service} ${owningTask} ${type} ${connect}`)

        if (result === KERN_SUCCESS && !connect.readPointer().isNull()) {
            if (func_IOObjectConformsTo(service, cstr_IOWatchdog)) {
                logw('got IOWatchdog')
                gIOWatchdogConnection = connect.readPointer()
            } else {
                logd('pass')
            }
        }
        return result
    }, 'int', ['pointer', 'pointer', 'uint', 'pointer']))

    const addr_IOConnectCallStructMethod = DebugSymbol.fromName("IOConnectCallStructMethod").address
    // kern_return_t IOConnectCallStructMethod(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt)
    const originalFunction = new NativeFunction(addr_IOConnectCallStructMethod, 'int', ['pointer', 'uint', 'pointer', 'ulong', 'pointer', 'pointer']);
    Interceptor.replace(addr_IOConnectCallStructMethod, new NativeCallback((connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt) => {
        console.log(`called IOConnectCallStructMethod ${connection} ${selector} ${inputStruct}`)
        if (connection.equals(gIOWatchdogConnection)) {
            logw(`connection.equals(gIOWatchdogConnection)`)
            if (selector === 2) {
                logw('connection.equals(gIOWatchdogConnection) and selector == 2')
                return KERN_SUCCESS
            }
        }
        return originalFunction(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt)
    }, 'int', ['pointer', 'uint', 'pointer', 'ulong', 'pointer', 'pointer']))








})
