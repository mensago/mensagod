package mensagod.messaging

import libkeycard.Domain
import libkeycard.WAddress
import mensagod.DBConn
import mensagod.MServerPath
import mensagod.WorkerPool
import mensagod.dbcmds.isDomainLocal
import mensagod.fs.LocalFS
import mensagod.logError
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Used for giving the necessary information for delivery threads to do their jobs.
 */
class MessageInfo(val sender: String, val receiver: String, val path: MServerPath)

// The global message queue for delivery threads to process work from.
private val gMessageQueue = ConcurrentLinkedQueue<MessageInfo>()
private val gDeliveryPool = WorkerPool(100)

/**
 * Add a MessageInfo object to the delivery queue. It also spawns a delivery thread to handle the
 * message if the thread pool is not running at capacity.
 */
fun queueMessageForDelivery(info: MessageInfo) {
    gMessageQueue.add(info)

    // TODO: Launch delivery thread
}

fun deliveryWorker(id: ULong) {

    val lfs = LocalFS.get()
    val db = DBConn()
    while (!gDeliveryPool.isQuitting()) {
        val msgInfo = gMessageQueue.poll() ?: break

        val handle = lfs.entry(msgInfo.path)
        val exists = handle.exists().getOrElse {
            logError("Invalid msgInfo path ${msgInfo.path}")
            return
        }
        if (!exists) {
            sendBounce(300, msgInfo, mapOf("INTERNALCODE" to "messaging.deliveryWorker.1"))
                ?.let { logError("Error sending deliveryWorker bounce #1: $it") }
            continue
        }

        val domain = Domain.fromString(msgInfo.receiver)
        if (domain == null) {
            logError("Bad domain ${msgInfo.receiver} for ${msgInfo.path}")
            continue
        }

        val isLocal = isDomainLocal(db, domain).getOrElse {
            logError("Error determining domain $domain is local: $it")
            return
        }

        if (isLocal) {
            val sealedEnv = SealedEnvelope.readFromFile(handle.getFile()).getOrElse {
                sendBounce(300, msgInfo,
                    mapOf("INTERNALCODE" to "messaging.deliveryWorker.2"))
                    ?.let { logError("Error sending deliveryWorker bounce #2: $it") }
                return
            }

            val recipientStr = sealedEnv.decryptReceiver().getOrElse {
                sendBounce(504, msgInfo, mapOf())
                    ?.let { logError("Error sending deliveryWorker bounce #3: $it") }
                return
            }

            val recipient = WAddress.fromString(recipientStr)
            if (recipient == null) {
                sendBounce(503, msgInfo, mapOf("RECIPIENTADDRESS" to recipientStr))
                    ?.let { logError("Error sending deliveryWorker bounce #4: $it") }
            }

            // TODO: Finish local delivery code in deliveryWorker()
        }

        // FEATURE: ExternalDelivery

        // External delivery is not needed for the MVP. For the moment, we'll just delete the
        // message and push a bounce message into the sender's workspace for now.
        sendBounce(301, msgInfo, mapOf())
        lfs.withLock(msgInfo.path) { handle.delete() }
            ?.let { logError("Couldn't delete ${msgInfo.path}: $it") }
    }

    gDeliveryPool.done(id)
}

private fun sendBounce(errorcode: Int, info: MessageInfo, extraData: Map<String,String>):
        Throwable? {
    TODO("Implement sendBounce($errorcode, $info, $extraData")
}
