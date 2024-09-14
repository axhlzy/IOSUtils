## Introduction

Completing a more comprehensive IOS reverse toolkit

## Realized Functions

- ` showMethods: (clsNameOrPtr: number | string | NativePointer, filter?: string, includeParent?: boolean) => void | alias m `
  
    ![1726305919449](https://github.com/user-attachments/assets/413bec15-bb7e-435e-9cd9-4c0919ebfc4f)

- ` findClasses: (query: string) => void `

    ![1724935124602](https://github.com/user-attachments/assets/33a60319-7780-4f02-be86-20a8258e77c4)
  
- ` dumpUI: () => void `

    ![1726306200793](https://github.com/user-attachments/assets/7cffe509-10ab-4a3e-9680-80eba2a1815e)

- ` showButtonActions: (ptr: NativePointer | number | string) => void `

    ![1726306269932](https://github.com/user-attachments/assets/cbe5ca83-d11c-4736-b2a9-e53892342c84)

- ` lfs: (ptr: NativePointer | string | number) => void `

    ![1726306420619](https://github.com/user-attachments/assets/d2d854d2-6345-4fc1-994c-13bb8c134733)


## Others
```
var hex: (ptr: NativePointer | string | number, len?: number) => void
var allocOCString: (str: string) => ObjC.Object
var call: (ptr: NativePointer | number | string | ObjC.Object, ...args: any | NativePointer | ObjC.Object) => NativePointer
var callOC: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => NativePointer
var callOcOnMain: (objPtr: NativePointer | string | number | ObjC.Object, funcName: string, ...args: any | NativePointer | ObjC.Object) => void
```


## THANKS
- [frida-ios-cipher](https://github.com/jitcor/frida-ios-cipher)
- [objection](https://github.com/sensepost/objection/tree/master/agent/src/ios)
- [xia0LLDB](https://github.com/4ch12dy/xia0LLDB/blob/0ea9f8d1020859daaefa0a52e7e0163eb3e3ed67/src/cmds.txt)
