package mensagod.commands

enum class FrameType {
    SingleFrame,
    MultipartFrameStart,
    MultipartFrame,
    MultipartFrameFinal,
    SessionSetupRequest,
    SessionSetupResponse,
    InvalidFrame;

    fun toByte(): Byte {
        return when (this) {
            SingleFrame -> 50
            MultipartFrameStart -> 51
            MultipartFrame -> 52
            MultipartFrameFinal -> 53
            SessionSetupRequest -> 54
            SessionSetupResponse -> 55
            InvalidFrame -> -1
        }
    }

    companion object {
        fun fromByte(value: Byte): FrameType {
            return when (value.toInt()) {
                50 -> SingleFrame
                51 -> MultipartFrameStart
                52 -> MultipartFrame
                53 -> MultipartFrameFinal
                54 -> SessionSetupRequest
                55 -> SessionSetupResponse
                else -> InvalidFrame
            }
        }
    }
}
