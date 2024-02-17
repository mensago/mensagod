package libmensago

import libkeycard.Timestamp
import libkeycard.WAddress
import java.net.InetAddress

/**
 * The DeviceApprovalMsg class represents a device approval message.
 */
class DeviceApprovalMsg private constructor(from: WAddress, to: WAddress):
    Message(from, to, MsgFormat.Text) {

    init {
        type = MsgType.System
        subType = "devrequest"
    }
    companion object {
        /**
         * Creates a new device approval message.
         */
        fun new(from: WAddress, to: WAddress, addr: InetAddress): Result<DeviceApprovalMsg> {
            val out = DeviceApprovalMsg(from, to)
            out.setSubject("New Device Login")

            val ts = Timestamp()
            // TODO: Implement DeviceApprovalMsg::new()

            return Result.success(out)
        }
    }
}
