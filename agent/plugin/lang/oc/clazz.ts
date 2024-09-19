export class ObjCClassIMPL extends ObjC.Object {

    constructor(mPtr:NativePointer){
        super(mPtr)
        if (this.$kind == "meta-class") throw new Error(`this ptr can not cast to class | current:${this.$kind}`)
    }

    get name(){
        return this.$className
    }

    public getName(){
        return this.$className
    }

    public toString(): string {
        return `C: ${this.implementation} ${this}`
    }
}

declare global{

    namespace ObjC {
        class Class extends ObjCClassIMPL{
            toString(): string
            getName():string
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
 