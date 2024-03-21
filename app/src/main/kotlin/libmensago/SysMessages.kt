package libmensago

import keznacl.*
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
        val addrStr = if (addr.toString().startsWith("/"))
            addr.toString().substring(1)
        else
            addr.toString()
        body = "Timestamp=$ts\r\nIP Address=$addrStr\r\n"
        attach(
            Attachment(
                "deviceinfo",
                MimeType.fromString("application/vnd.mensago.encrypted-json")!!,
                devInfo.toString().encodeToByteArray()
            )
        )
    }

    companion object {

        /**
         * Decrypts the attached device info on an approval message and returns the expected message
         * body to be presented to the user after possible other processing.
         */
        fun getApprovalInfo(userPair: EncryptionPair, msg: Message): Result<Map<String, String>> {
            if (msg.attachments.size < 1)
                return MissingDataException("DeviceInfo attachment missing").toFailure()

            val attach = msg.attachments[0]
            if (attach.name != "deviceinfo" ||
                attach.mime.toString() != "application/vnd.mensago.encrypted-json"
            ) {
                return BadValueException("First attachment is not deviceinfo").toFailure()
            }
            val cs = CryptoString.fromString(attach.data.decodeToString())
                ?: return BadValueException("Bad deviceinfo attachment data").toFailure()
            val infoStr = userPair.decrypt(cs).getOrElse { return it.toFailure() }.decodeToString()

            val items = msg.body.trim().split("\r\n")
                .plus(infoStr.trim().split("\r\n"))
            return items.associate { line ->
                line.trim().split("=", limit = 2).let { Pair(it[0], it[1]) }
            }.toSuccess()
        }
    }
}
