export { }

// typedef NS_OPTIONS(NSUInteger, UIControlEvents) {
//     UIControlEventTouchDown                                         = 1 <<  0,      // on all touch downs
//     UIControlEventTouchDownRepeat                                   = 1 <<  1,      // on multiple touchdowns (tap count > 1)
//     UIControlEventTouchDragInside                                   = 1 <<  2,
//     UIControlEventTouchDragOutside                                  = 1 <<  3,
//     UIControlEventTouchDragEnter                                    = 1 <<  4,
//     UIControlEventTouchDragExit                                     = 1 <<  5,
//     UIControlEventTouchUpInside                                     = 1 <<  6,
//     UIControlEventTouchUpOutside                                    = 1 <<  7,
//     UIControlEventTouchCancel                                       = 1 <<  8,

//     UIControlEventValueChanged                                      = 1 << 12,     // sliders, etc.
//     UIControlEventPrimaryActionTriggered API_AVAILABLE(ios(9.0))    = 1 << 13,     // semantic action: for buttons, etc.
//     UIControlEventMenuActionTriggered API_AVAILABLE(ios(14.0))      = 1 << 14,     // triggered when the menu gesture fires but before the menu presents

//     UIControlEventEditingDidBegin                                   = 1 << 16,     // UITextField
//     UIControlEventEditingChanged                                    = 1 << 17,
//     UIControlEventEditingDidEnd                                     = 1 << 18,
//     UIControlEventEditingDidEndOnExit                               = 1 << 19,     // 'return key' ending editing

//     UIControlEventAllTouchEvents                                    = 0x00000FFF,  // for touch events
//     UIControlEventAllEditingEvents                                  = 0x000F0000,  // for UITextField
//     UIControlEventApplicationReserved                               = 0x0F000000,  // range available for application use
//     UIControlEventSystemReserved                                    = 0xF0000000,  // range reserved for internal framework use
//     UIControlEventAllEvents                                         = 0xFFFFFFFF
// };
enum UIControlEvents {
    UNDEF = 0,
    EventTouchDown = 1 << 0,
    EventTouchDownRepeat = 1 << 1,
    EventTouchDragInside = 1 << 2,
    EventTouchDragOutside = 1 << 3,
    EventTouchDragEnter = 1 << 4,
    EventTouchDragExit = 1 << 5,
    EventTouchUpInside = 1 << 6,
    EventTouchUpOutside = 1 << 7,
    EventTouchCancel = 1 << 8,
    EventValueChanged = 1 << 12,
    EventPrimaryActionTriggered = 1 << 13,
    EventMenuActionTriggered = 1 << 14,
    EventEditingDidBegin = 1 << 16,
    EventEditingChanged = 1 << 17,
    EventEditingDidEnd = 1 << 18,
    EventEditingDidEndOnExit = 1 << 19,
    EventAllTouchEvents = 0x00000FFF,
    EventAllEditingEvents = 0x000F0000,
    EventApplicationReserved = 0x0F000000,
    EventSystemReserved = 0xF0000000,
    EventAllEvents = 0xFFFFFFFF
}

// iVar        Value
// ----------  -------------------------
// isa         {'handle': '0x203101748'}
// _target     {'handle': '0x13f111ff0'}
// _action     0x1044ba8a0
// _eventMask  64
// _cancelled  False
class UIControlTargetAction {
    private isa: NativePointer = NULL
    private _target: NativePointer = NULL
    private _action: NativePointer = NULL
    private _eventMask: UIControlEvents = UIControlEvents.UNDEF
    private _cancelled: boolean = false

    private _target_ins : ObjC.Object
    private _action_str : string

    public constructor(ptr: NativePointer) {
        this.isa = ptr.readPointer()
        this._target = ptr.add(1 * Process.pointerSize).readPointer()
        this._action = ptr.add(2 * Process.pointerSize).readPointer()
        this._eventMask = ptr.add(3 * Process.pointerSize).readU32()
        this._cancelled = ptr.add(3 * Process.pointerSize + 4).readU8() != 0

        this._target_ins = new ObjC.Object(this._target)
        this._action_str = this._action.readCString()!
    }

    public parseAction(): string {
        const _fullName = this._target_ins.$methods.filter(i => i.includes(this._action_str))[0]
        const _action_method = this._target_ins.$class[_fullName]
        return `${ptr(_action_method)} -> ${_action_method.implementation}`
    }

    toString() {
        return `target: ${this._target_ins}\n\taction: ${this._action} | '${this._action_str}' | ${this.parseAction()}\n\teventMask: ${this._eventMask}, cancelled: ${this._cancelled}`
    }
}

const showButtonActions = (ptr: NativePointer | number | string) => {
    const mPtr = checkPointer(ptr)
    let obj = new ObjC.Object(mPtr)
    if (!getSuperClasses(mPtr).map(i => i.$className).includes("UIButton")){
        // UIButtonLabel props ↓
        // UIButtonLabel extends UILabel ? Four new member variables have been added ?
        // ......
        // [68] _reverseShadow: | boolean
        //         false
        // [69] _button: | ObjC.Object <- instance of UPXCommonButton @ 0x1060b72b0
        //         0x107da0cc0
        // [70] _cachedDefaultAttributes: | ObjC.Object <- instance of __NSDictionaryM @ 0x1dc788050
        //         0x2820daee0
        // [71] _fontIsDefaultForIdiom: | boolean
        //         false
        if (getFields(mPtr).includes("_button")){
            obj = obj.$ivars["_button"]
        } else {
            throw new Error(`pointer --//--> class extends UIButton ${ObjC.classes['UIButton']} ? C:${obj}`)
        }
    }
    const actions = obj.$ivars["_targetActions"]
    if (actions.isNull()) throw new Error(`targetActions == ${actions} }`)
    const count = actions["- count"]() as number
    for (let i = 0; i < count; i++) {
        const item_obj: ObjC.Object = actions["- objectAtIndex:"](i)
        const item: UIControlTargetAction = new UIControlTargetAction(item_obj.handle)
        logd(`[${i}] ${item}`)
    }
}

declare global {
    var showButtonActions: (ptr: NativePointer | number | string) => void
}

globalThis.showButtonActions = showButtonActions