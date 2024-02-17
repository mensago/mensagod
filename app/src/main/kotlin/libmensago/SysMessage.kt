package libmensago

import libkeycard.Timestamp
import libkeycard.WAddress
import java.net.InetAddress

/**
 * Class which represents a Mensago system message.
 */
open class SysMessage(from: WAddress, to: WAddress, var subtype: String):
    Message(from, to, MsgFormat.Text)

/**
 * The DeviceApprovalMsg class represents a device approval message.
 */
class DeviceApprovalMsg private constructor(from: WAddress, to: WAddress):
    SysMessage(from, to, "devrequest") {

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
