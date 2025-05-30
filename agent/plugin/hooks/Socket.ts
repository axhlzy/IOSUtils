globalThis.hook_socket_io = (printBackTrace: boolean = true) => {
    try {
        // Find the module where socket functions are located
        // Usually in libSystem.dylib or libc.dylib
        const module = Process.findModuleByName("libsystem_c.dylib");

        if (module) {
            logd(`[+] Found C standard library module: ${module.name}`);

            // Hook send
            const send_ptr = module.getExportByName("send");
            if (send_ptr) {
                Interceptor.attach(send_ptr, {
                    onEnter: function(args) {
                        logw(`[+] send called`);
                        // args[0] is int sockfd (socket file descriptor)
                        // args[1] is const void *buf (buffer to send)
                        // args[2] is size_t len (number of bytes to send)
                        // args[3] is int flags

                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        const flags = args[3].toInt32();

                        logd(`  Socket FD: ${sockfd}`);
                        logd(`  Buffer address: ${buf}`);
                        logd(`  Length: ${len}`);
                        logd(`  Flags: ${flags}`);

                        // Optional: Print data being sent
                        if (!buf.isNull() && len > 0) {
                            try {
                                // const dataBytes = buf.readByteArray(Math.min(len, 128)); // Print first 128 bytes
                                logo("  Data sent (first 128 bytes hex):");
                                logz(hexdump(buf, { offset: 0, length: Math.min(len, 128), header: true, ansi: false }));
                                // Attempt to convert to string (if it's text data)
                                // try {
                                //     const dataString = Memory.readUtf8String(buf, Math.min(len, 512)); // Read up to 512 bytes as UTF8 string
                                //     logz(`  Data sent (string): ${dataString}`);
                                // } catch (e) {
                                //     loge("  Error reading data sent as string:" + e);
                                // }
                            } catch (e) {
                                loge("  Error reading data sent:" + e);
                            }
                        }

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }
                    }
                    // onLeave can be used to check the return value (bytes sent)
                });
                logd("[+] Successfully hooked send");
            } else {
                logw("[-] Could not find symbol _send. Check module name or symbol.");
            }

            // Hook recv
            const recv_ptr = module.getExportByName("recv");
            if (recv_ptr) {
                Interceptor.attach(recv_ptr, {
                    onEnter: function(args) {
                        logw(`[+] recv called`);
                        // args[0] is int sockfd (socket file descriptor)
                        // args[1] is void *buf (buffer to receive into)
                        // args[2] is size_t len (buffer size)
                        // args[3] is int flags

                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        const flags = args[3].toInt32();

                        logd(`  Socket FD: ${sockfd}`);
                        logd(`  Buffer address: ${buf}`);
                        logd(`  Buffer size: ${len}`);
                        logd(`  Flags: ${flags}`);

                        // We can't print the received data in onEnter, as it hasn't been read yet.
                        // We'll print it in onLeave.

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }

                        // Store buf address for onLeave
                        this.buf = buf;
                    },
                    onLeave: function(retval) {
                        // retval is the number of bytes received, or -1 on error
                        const bytesReceived = retval.toInt32();
                        logd(`[+] recv returned: ${bytesReceived} bytes`);

                        // Print received data if successful
                        if (bytesReceived > 0 && this.buf && !this.buf.isNull()) {
                             try {
                                const dataBytes = this.buf.readByteArray(Math.min(bytesReceived, 128)); // Print first 128 bytes
                                logo("  Data received (first 128 bytes hex):");
                                logz(hexdump(dataBytes, { offset: 0, length: Math.min(bytesReceived, 128), header: true, ansi: false }));
                                 // Attempt to convert to string (if it's text data)
                                // try {
                                //     const dataString = Memory.readUtf8String(this.buf, Math.min(bytesReceived, 512)); // Read up to 512 bytes as UTF8 string
                                //     logz(`  Data received (string): ${dataString}`);
                                // } catch (e) {
                                //     loge("  Error reading data received as string:" + e);
                                // }
                            } catch (e) {
                                loge("  Error reading data received:" + e);
                            }
                        }
                        logz("--------------------");
                    }
                });
                logd("[+] Successfully hooked recv");
            } else {
                logw("[-] Could not find symbol _recv. Check module name or symbol.");
            }

            // Hook sendto (for UDP)
            const sendto_ptr = module.getExportByName("sendto");
            if (sendto_ptr) {
                Interceptor.attach(sendto_ptr, {
                    onEnter: function(args) {
                        logw(`[+] sendto called`);
                        // args[0] is int sockfd
                        // args[1] is const void *buf
                        // args[2] is size_t len
                        // args[3] is int flags
                        // args[4] is const struct sockaddr *dest_addr
                        // args[5] is socklen_t addrlen

                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        const flags = args[3].toInt32();
                        const dest_addr = args[4];
                        const addrlen = args[5].toInt32();

                        logd(`  Socket FD: ${sockfd}`);
                        logd(`  Buffer address: ${buf}`);
                        logd(`  Length: ${len}`);
                        logd(`  Flags: ${flags}`);
                        logd(`  Destination address address: ${dest_addr}`);
                        logd(`  Address length: ${addrlen}`);

                        // Optional: Print destination address details (requires parsing sockaddr structure)
                        if (!dest_addr.isNull() && addrlen >= 2) { // Minimum size for sockaddr_in/sockaddr_in6
                            try {
                                const sa_family = dest_addr.readU16(); // sa_family_t
                                logd(`  Address Family: ${sa_family === 2 ? 'AF_INET' : (sa_family === 30 ? 'AF_INET6' : 'Unknown')}`);
                                if (sa_family === 2 && addrlen >= 16) { // sockaddr_in
                                    const sin_port = dest_addr.add(2).readU16(); // Port is at offset 2
                                    // const sin_addr = dest_addr.add(4).readByteArray(4); // IP address is at offset 4
                                    // logd(`  Destination Port (AF_INET): ${socket.ntohs(sin_port)}`); // Convert network byte order to host byte order
                                    // logd(`  Destination IP (AF_INET): ${sin_addr.join('.')}`); // Simple representation
                                } else if (sa_family === 30 && addrlen >= 28) { // sockaddr_in6
                                     const sin6_port = dest_addr.add(2).readU16(); // Port is at offset 2
                                     // IPv6 address is at offset 8, 16 bytes
                                     const sin6_addr = dest_addr.add(8).readByteArray(16);
                                    //  logd(`  Destination Port (AF_INET6): ${socket.ntohs(sin6_port)}`);
                                     // More complex to represent IPv6 hex string
                                }
                            } catch (e) {
                                loge("  Error parsing destination address:" + e);
                            }
                        }


                        // Optional: Print data being sent (same as send)
                        if (!buf.isNull() && len > 0) {
                            try {
                                // const dataBytes = buf.readByteArray(Math.min(len, 128)); // Print first 128 bytes
                                logo("  Data sent (first 128 bytes hex):");
                                logz(hexdump(buf, { offset: 0, length: Math.min(len, 128), header: true, ansi: false }));
                            } catch (e) {
                                loge("  Error reading data sent:" + e);
                            }
                        }


                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }
                    }
                    // onLeave can be used to check the return value (bytes sent)
                });
                logd("[+] Successfully hooked sendto");
            } else {
                logw("[-] Could not find symbol _sendto. Check module name or symbol.");
            }

            // Hook recvfrom (for UDP)
            const recvfrom_ptr = module.getExportByName("recvfrom");
            if (recvfrom_ptr) {
                Interceptor.attach(recvfrom_ptr, {
                    onEnter: function(args) {
                        logw(`[+] recvfrom called`);
                        // args[0] is int sockfd
                        // args[1] is void *buf
                        // args[2] is size_t len
                        // args[3] is int flags
                        // args[4] is struct sockaddr *src_addr
                        // args[5] is socklen_t *addrlen

                        const sockfd = args[0].toInt32();
                        const buf = args[1];
                        const len = args[2].toInt32();
                        const flags = args[3].toInt32();
                        const src_addr = args[4]; // Pointer to sockaddr structure
                        const addrlen_ptr = args[5]; // Pointer to socklen_t

                        logd(`  Socket FD: ${sockfd}`);
                        logd(`  Buffer address: ${buf}`);
                        logd(`  Buffer size: ${len}`);
                        logd(`  Flags: ${flags}`);
                        logd(`  Source address address: ${src_addr}`);
                        logd(`  Address length pointer: ${addrlen_ptr}`);

                        // We can't print the received data or source address in onEnter.
                        // We'll print them in onLeave.

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }

                        // Store buf address, src_addr address, and addrlen_ptr for onLeave
                        this.buf = buf;
                        this.src_addr = src_addr;
                        this.addrlen_ptr = addrlen_ptr;
                    },
                    onLeave: function(retval) {
                        // retval is the number of bytes received, or -1 on error
                        const bytesReceived = retval.toInt32();
                        logd(`[+] recvfrom returned: ${bytesReceived} bytes`);

                        // Print received data if successful
                        if (bytesReceived > 0 && this.buf && !this.buf.isNull()) {
                             try {
                                const dataBytes = this.buf.readByteArray(Math.min(bytesReceived, 128)); // Print first 128 bytes
                                logo("  Data received (first 128 bytes hex):");
                                logz(hexdump(dataBytes, { offset: 0, length: Math.min(bytesReceived, 128), header: true, ansi: false }));
                            } catch (e) {
                                loge("  Error reading data received:" + e);
                            }
                        }

                        // Print source address if successful and address buffer was provided
                        if (bytesReceived >= 0 && this.src_addr && !this.src_addr.isNull() && this.addrlen_ptr && !this.addrlen_ptr.isNull()) {
                            try {
                                const addrlen = this.addrlen_ptr.readU32(); // Read the actual address length written by recvfrom
                                if (addrlen >= 2) {
                                    const sa_family = this.src_addr.readU16();
                                    logd(`  Source Address Family: ${sa_family === 2 ? 'AF_INET' : (sa_family === 30 ? 'AF_INET6' : 'Unknown')}`);
                                    if (sa_family === 2 && addrlen >= 16) { // sockaddr_in
                                        const sin_port = this.src_addr.add(2).readU16();
                                        const sin_addr = this.src_addr.add(4).readByteArray(4);
                                        // logd(`  Source Port (AF_INET): ${socket.ntohs(sin_port)}`);
                                        logd(`  Source IP (AF_INET): ${sin_addr.join('.')}`);
                                    } else if (sa_family === 30 && addrlen >= 28) { // sockaddr_in6
                                        const sin6_port = this.src_addr.add(2).readU16();
                                        const sin6_addr = this.src_addr.add(8).readByteArray(16);
                                        // logd(`  Source Port (AF_INET6): ${socket.ntohs(sin6_port)}`);
                                        // More complex to represent IPv6 hex string
                                    }
                                }
                            } catch (e) {
                                loge("  Error parsing source address:" + e);
                            }
                        }
                        logz("--------------------");
                    }
                });
                logd("[+] Successfully hooked recvfrom");
            } else {
                logw("[-] Could not find symbol _recvfrom. Check module name or symbol.");
            }


            // Optional: Hook write and read as they can also be used for sockets
            // const write_ptr = module.getExportByName("write");
            // if (write_ptr) {
            //     Interceptor.attach(write_ptr, {
            //         onEnter: function(args) {
            //             const fd = args[0].toInt32();
            //             // You need to determine if this file descriptor is a socket
            //             // This is complex and might require hooking socket creation functions (socket, accept, connect)
            //             // and keeping track of socket file descriptors.
            //             // If you can determine it's a socket, you can print data similar to send.
            //         }
            //     });
            //     logd("[+] Successfully hooked write (optional)");
            // } else {
            //     logw("[-] Could not find symbol _write.");
            // }

            // const read_ptr = module.getExportByName("read");
            // if (read_ptr) {
            //     Interceptor.attach(read_ptr, {
            //         onEnter: function(args) {
            //             const fd = args[0].toInt32();
            //             // Similar to write, determine if fd is a socket.
            //             // If it is, store buffer for onLeave and print data similar to recv.
            //         }
            //     });
            //     logd("[+] Successfully hooked read (optional)");
            // } else {
            //     logw("[-] Could not find symbol _read.");
            // }


        } else {
            loge("[-] Could not find C standard library module (libSystem.dylib or libc.dylib).");
        }

    } catch (e) {
        loge("[-] Error hooking socket functions:" + e);
    }

}

export { }

declare global {
    var hook_socket_io: (printBackTrace?: boolean) => void
}
