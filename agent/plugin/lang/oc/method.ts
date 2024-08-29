export class ObjCMethodIMPL extends ObjC.Object {

    toString(): string {
        return `C: ${this.implementation} ${this}`
    }
 
}

declare global{

    namespace ObjC {
        class Method extends ObjC.Object{
            toString(): string
        }
    }

}

globalThis.ObjC.Method = ObjCMethodIMPL