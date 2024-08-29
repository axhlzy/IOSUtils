export class ObjCClassIMPL extends ObjC.Object {

    toString(): string {
        return `C: ${this.implementation} ${this}`
    }
 
}

declare global{

    namespace ObjC {
        class Class extends ObjCClassIMPL{
            toString(): string
        }
    }

}

globalThis.ObjC.Class = ObjCClassIMPL

// Reflect.setPrototypeOf(ObjCClassIMPL.prototype, ObjC.Object.prototype)

// Object.defineProperty(ObjCClassIMPL.prototype, "toString", {
//     value: function toString(): string {
//         return `C:`
//     }
// })
 