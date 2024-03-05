package libmensago

import keznacl.CryptoString
import libkeycard.Timestamp
import libkeycard.WAddress
import java.net.InetAddress

/**
 * The DeviceApprovalMsg class represents a device approval message.
 */
class DeviceApprovalMsg(from: WAddress, to: WAddress, addr: InetAddress, devInfo: CryptoString) :
    Message(from, to, MsgFormat.Text) {

    init {
        type = MsgType.System
        subType = "devrequest"
        subject = "New Device Login"

        val ts = Timestamp()
        body = "Timestamp:$ts\r\nIP-Address:$addr\r\n"
        attach(
            Attachment(
                "deviceinfo",
                MimeType.fromString("application/vnd.mensago.encrypted-json")!!,
                devInfo.toString().encodeToByteArray()
            )
        )
    }
}
