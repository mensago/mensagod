package mensagod.delivery

import libkeycard.*
import libmensago.*
import mensagod.*
import mensagod.dbcmds.*
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Used for giving the necessary information for delivery threads to do their jobs.
 */
class MessageInfo(val sender: DeliveryTarget, val receiver: DeliveryTarget, val path: MServerPath)

// The global message queue for delivery threads to process work from.
private val gMessageQueue = ConcurrentLinkedQueue<MessageInfo>()
private val gDeliveryPool = WorkerPool(100)

/**
 * Add a MessageInfo object to the delivery queue. It also spawns a delivery thread to handle the
 * message if the thread pool is not running at capacity.
 */
fun queueMessageForDelivery(sender: WAddress, domain: Domain, path: MServerPath) {
    val info = MessageInfo(
        DeliveryTarget(sender.domain, sender.id),
        DeliveryTarget(domain), path
    )
    gMessageQueue.add(info)

    Thread.ofVirtual().start { deliveryWorker() }
}

fun deliveryWorker() {

    val lfs = LocalFS.get()
    val db = DBConn()
    while (!gDeliveryPool.isQuitting()) {
        val msgInfo = gMessageQueue.poll() ?: break

        val handle = lfs.entry(msgInfo.path)
        var exists = handle.exists().getOrElse {
            logError("Invalid msgInfo path ${msgInfo.path}")
            return
        }
        if (!exists) {
            sendBounce(300, msgInfo, mapOf("InternalCode" to "delivery.deliveryWorker.1"))
                ?.let { logError("Error sending deliveryWorker bounce #1: $it") }
            continue
        }

        val isLocal = isDomainLocal(db, msgInfo.receiver.domain).getOrElse {
            logError("Error determining domain ${msgInfo.receiver.domain} is local: $it")
            return
        }

        if (isLocal) {
            val sealedEnv = SealedDeliveryTag.readFromFile(handle.getFile()).getOrElse {
                sendBounce(
                    300, msgInfo,
                    mapOf("InternalCode" to "delivery.deliveryWorker.2")
                )
                    ?.let { logError("Error sending deliveryWorker bounce #2: $it") }
                return
            }

            val orgKeyPair = getEncryptionPair(db).getOrElse {
                logError("deliveryWorker: Unable to get the org encryption pair: $it")
                return
            }
            val recipientInfo = sealedEnv.decryptReceiver(orgKeyPair).getOrElse {
                sendBounce(504, msgInfo, mapOf())
                    ?.let { logError("Error sending deliveryWorker bounce #3: $it") }
                return
            }

            val destHandle = lfs.entry(MServerPath("/ wsp ${recipientInfo.to.id} new"))
            exists = destHandle.exists().getOrElse {
                logError("Unable to check for path ${destHandle.path}")
                return
            }
            if (!exists) {
                try {
                    destHandle.getFile().mkdirs()
                } catch (e: Exception) {
                    logError("Unable to check for path ${destHandle.path}")
                    return
                }
            }

            handle.moveTo(destHandle.path)?.let {
                logError("Unable to move ${handle.path} to ${destHandle.path}: $it")
                return
            }

            val finalPath = destHandle.path.clone()
            finalPath.push(handle.path.basename()).getOrElse {
                logError("Error creating final path for ${handle.path}: $it")
                return
            }
            addUpdateRecord(
                db, recipientInfo.to.id, UpdateRecord(
                    RandomID.generate(), UpdateType.Create, finalPath.toString(),
                    Instant.now().epochSecond.toString(), gServerDevID
                )
            )
        }

        // FEATURE: ExternalDelivery
        // FeatureTODO: Send message externally

        // External delivery is not needed for the MVP. For the moment, we'll just delete the
        // message and push a bounce message into the sender's workspace for now.
        sendBounce(301, msgInfo, mapOf())
        lfs.withLock(msgInfo.path) { handle.delete() }
            ?.let { logError("Couldn't delete ${msgInfo.path}: $it") }
    }
}

private fun sendBounce(errorCode: Int, info: MessageInfo, extraData: Map<String, String>):
        Throwable? {

    val db = DBConn()
    val orgPair = getEncryptionPair(db).getOrElse { return it }
    val userEntry = KCCache.getCurrentEntry(info.receiver.toEntrySubject()).getOrElse { return it }
    val domStr = userEntry.getFieldString("Domain")
        ?: return BadFieldValueException("Entry for user missing Domain field")
    val userWidStr = userEntry.getFieldString("Workspace-ID")
        ?: return BadFieldValueException("Entry for user missing Workspace-ID field")
    val userAddr = WAddress.fromString("$userWidStr:$domStr")
        ?: return BadFieldValueException("Bad workspace address from user entry")

    val msg = Message(gServerAddress, userAddr, MsgFormat.Text)
    when (errorCode) {
        300 -> {
            msg.subject = "Delivery Report: Internal Server Error"
            msg.body = "The server was unable to delivery your message because of an internal " +
                    "error. Please contact technical support for your account with the " +
                    "information provide below.\r\n\r\n" +
                    "----------\r\n" +
                    "Technical Support Information\r\n" +
                    "Error Code: 300 INTERNAL SERVER ERROR" +
                    "Internal Error Code: ${extraData["InternalCode"]!!}" +
                    "Date: ${Timestamp()}"
        }

        301 -> {
            msg.subject = "Delivery Report: External Delivery Not Implemented"
            msg.body = "The server was unable to deliver your message because external delivery" +
                    "is not yet implemented. Sorry!"
        }

        503 -> {
            msg.subject = "Delivery Report: Unreadable Recipient Address"
            msg.body = "The server was unable to deliver your message because the recipient's " +
                    "address was formatted incorrectly.\r\n\r\n" +
                    "----------\r\n" +
                    "Technical Support Information\r\n" +
                    "Error Code: 503 BAD RECIPIENT ADDRESS" +
                    "Date: ${Timestamp()}"
        }

        504 -> {
            msg.subject = "Delivery Report: Unreadable Recipient Address"
            msg.body = "The server was unable to deliver your message because it was unable to " +
                    "decrypt the recipient's address. This might be a problem with your " +
                    "program.\r\n\r\n" +
                    "----------\r\n" +
                    "Technical Support Information\r\n" +
                    "Error Code: 504 UNREADABLE RECIPIENT ADDRESS" +
                    "Date: ${Timestamp()}"
        }
    }

    TODO("Implement sendBounce($errorCode, $info, $extraData")
}
