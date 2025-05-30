globalThis.hook_network = (printBackTrace: boolean = true) => {
    if (ObjC.available) {
        try {
            // Get the NSURLSession class
            const NSURLSession = ObjC.classes.NSURLSession;
            // Get the NSURLRequest class (to inspect the request object)
            const NSURLRequest = ObjC.classes.NSURLRequest;

            // Hook -[NSURLSession dataTaskWithRequest:completionHandler:]
            const dataTaskWithRequest_completionHandler_ptr = NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation;
            if (dataTaskWithRequest_completionHandler_ptr) {
                Interceptor.attach(dataTaskWithRequest_completionHandler_ptr, {
                    onEnter: function(args) {
                        logw(`[+] -[NSURLSession dataTaskWithRequest:completionHandler:] called`);
                        // args[0] is the self (NSURLSession instance)
                        // args[1] is the selector (- dataTaskWithRequest:completionHandler:)
                        // args[2] is the NSURLRequest instance
                        // args[3] is the completion handler Block

                        const request = new ObjC.Object(args[2]); // Get the NSURLRequest object

                        // Print request details
                        try {
                            const url = request.URL().toString();
                            const method = request.HTTPMethod().toString();
                            const headers = request.allHTTPHeaderFields(); // NSDictionary

                            logd(`  URL: ${url}`);
                            logd(`  Method: ${method}`);
                            logd(`  Headers: ${headers}`); // Prints NSDictionary description

                            // Optional: Print HTTP body (be cautious with large bodies)
                            // const httpBody = request.HTTPBody(); // NSData
                            // if (!httpBody.isNull()) {
                            //     const bodyLength = httpBody.length();
                            //     logd(`  HTTP Body Length: ${bodyLength}`);
                            //     if (bodyLength > 0) {
                            //         const bodyBytes = Memory.readByteArray(httpBody.bytes(), Math.min(bodyLength, 128)); // Print first 128 bytes
                            //         logo("  HTTP Body (first 128 bytes hex):");
                            //         logz(hexdump(bodyBytes, { offset: 0, length: Math.min(bodyLength, 128), header: true, ansi: false }));
                            //         // Attempt to convert to string (if it's text data)
                            //         // try {
                            //         //     const bodyString = Memory.readUtf8String(httpBody.bytes(), Math.min(bodyLength, 512)); // Read up to 512 bytes as UTF8 string
                            //         //     logz(`  HTTP Body (string): ${bodyString}`);
                            //         // } catch (e) {
                            //         //     loge("  Error reading HTTP body as string:" + e);
                            //         // }
                            //     }
                            // }


                        } catch (e) {
                            loge("  Error inspecting NSURLRequest:" + e);
                        }

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }
                    }
                    // No onLeave needed for this hook, as we are interested in the request creation
                });
                logd("[+] Successfully hooked -[NSURLSession dataTaskWithRequest:completionHandler:]");
            } else {
                 logw("[-] Could not find implementation for -[NSURLSession dataTaskWithRequest:completionHandler:].");
            }

            // Optional: Hook other NSURLSession data task creation methods if needed
            // -[NSURLSession dataTaskWithURL:completionHandler:]
            // -[NSURLSession dataTaskWithRequest:]
            // -[NSURLSession dataTaskWithURL:]

            // Optional: Hook NSURLSessionTask resume method to see when the task starts
            const NSURLSessionTask = ObjC.classes.NSURLSessionTask;
            const resume_ptr = NSURLSessionTask["- resume"].implementation;
            if (resume_ptr) {
                Interceptor.attach(resume_ptr, {
                    onEnter: function(args) {
                        logw(`[+] -[NSURLSessionTask resume] called`);
                        // args[0] is the self (NSURLSessionTask instance)
                        // args[1] is the selector (- resume)

                        const task = new ObjC.Object(args[0]);
                        try {
                            const originalRequest = task.originalRequest(); // NSURLRequest
                            if (!originalRequest.isNull()) {
                                const url = originalRequest.URL().toString();
                                logd(`  Task URL: ${url}`);
                            }
                        } catch (e) {
                            loge("  Error getting task original request:" + e);
                        }

                        if (printBackTrace) {
                            logo("Call Stack:")
                            logz(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'))
                            logz("--------------------")
                        }
                    }
                });
                logd("[+] Successfully hooked -[NSURLSessionTask resume]");
            } else {
                 logw("[-] Could not find implementation for -[NSURLSessionTask resume].");
            }


        } catch (e) {
            loge("[-] Error hooking network methods:" + e);
        }
    } else {
        loge("[-] Objective-C runtime not available");
    }

}

export { }

declare global {
    var hook_network: (printBackTrace?: boolean) => void
}