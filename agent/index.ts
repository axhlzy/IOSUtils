import './include.js'
import './logger.js'

declare global {
    var d : () => void
}

globalThis.d = () =>{
    Interceptor.detachAll()
}