package mensagod.delivery

import keznacl.onFalse
import keznacl.toFailure
import keznacl.toSuccess
import libkeycard.*
import libmensago.*
import libmensago.resolver.KCResolver
import mensagod.*
import mensagod.dbcmds.*
import java.lang.Thread.currentThread
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Used for giving the necessary information for delivery threads to do their jobs.
 */
class MessageInfo(val sender: DeliveryTarget, val receiver: DeliveryTarget, val path: MServerPath)

// The global message queue for delivery threads to process work from.
private val gMessageQueue = ConcurrentLinkedQueue<MessageInfo>()
private val gConcurrentMap = ConcurrentHashMap<Thread, Boolean>()
private val gDeliveryThreads = Collections.newSetFromMap(gConcurrentMap)
private val gQuitDeliveryThreads = AtomicBoolean(false)

/**
 * Add a MessageInfo object to the delivery queue. It also spawns a delivery thread to handle the
 * message if the thread pool is not running at capacity.
 */
fun queueMessageForDelivery(sender: WAddress, domain: Domain, path: MServerPath): Thread {
    val info = MessageInfo(
        DeliveryTarget(sender.domain, sender.id),
        DeliveryTarget(domain), path
    )
    gMessageQueue.add(info)

    return Thread.ofVirtual().start { deliveryWorker() }
}

fun shutdownDeliveryThreads() {
    gQuitDeliveryThreads.set(true)
    while (gDeliveryThreads.size > 0)
        gDeliveryThreads.first().join()
}

/**
 * This function only exists for testing. It merely turns off the flag signalling quitting time for
 * delivery threads
 */
fun resetDelivery() {
    gQuitDeliveryThreads.set(false)
}

fun deliveryWorker() {

    val lfs = LocalFS.get()
    val db = runCatching { DBConn() }.getOrElse { return }
    gDeliveryThreads.add(currentThread())
    do {
        val msgInfo = gMessageQueue.poll() ?: break

        val isRecipientLocal = isDomainLocal(db, msgInfo.receiver.domain).getOrElse {
            logError("Error determining domain ${msgInfo.receiver.domain} is local: $it")
            return
        }

        val handle = lfs.entry(msgInfo.path)
        val exists = handle.exists().getOrElse {
            logError("Invalid msgInfo path ${msgInfo.path}")
            return
        }
        if (!exists) {
            sendBounce(300, msgInfo, mapOf("InternalCode" to "delivery.deliveryWorker.1"))
                ?.let { logError("Error sending deliveryWorker bounce #1: $it") }
            continue
        }

        if (isRecipientLocal) {
            deliverToMailbox(db, handle, msgInfo)
            continue
        }

        // FEATURE: ExternalDelivery
        // FeatureTODO: Send message externally

        // External delivery is not needed for the MVP. For the moment, we'll just delete the
        // message and push a bounce message into the sender's workspace for now.
        sendBounce(301, msgInfo, mapOf())?.let {
            logError("Error bouncing message to ${msgInfo.receiver}: $it")
        }
        lfs.withLock(msgInfo.path) { handle.delete() }
            ?.let { logError("Couldn't delete ${msgInfo.path}: $it") }

    } while (!gQuitDeliveryThreads.get())
    db.disconnect()
    gDeliveryThreads.remove(currentThread())
}

/**
 * Handles final-mile processing of a message for delivery to a local mailbox
 */
fun deliverToMailbox(db: DBConn, handle: LocalFSHandle, msgInfo: MessageInfo) {
    val sealedEnv = SealedDeliveryTag.readFromFile(handle.getFile()).getOrElse {
        sendBounce(
            300, msgInfo,
            mapOf("InternalCode" to "delivery.deliveryWorker.2")
        )?.let { logError("Error sending deliveryWorker bounce #2: $it") }
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

    val lfs = LocalFS.get()
    val destHandle = lfs.entry(MServerPath("/ wsp ${recipientInfo.to.id} new"))
    destHandle.exists().getOrElse {
        logError("Unable to check for path ${destHandle.path}")
        return
    }.onFalse {
        runCatching { destHandle.getFile().mkdirs() }
            .onFailure {
                logError("Unable to create path ${destHandle.path}: $it")
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
    addSyncRecord(
        db, recipientInfo.to.id, SyncRecord(
            RandomID.generate(), UpdateType.Create, finalPath.toString(),
            Instant.now().epochSecond.toString(), gServerDevID
        )
    )
}

/**
 * sendBounce is used to construct delivery failure report (bounce) messages based on the failure
 * code.
 *
 * @param errorCode The Mensago error code
 * @param info The delivery information
 * @param extraData A map for passing extra message-related data to the call; it is needed for
 * certain error codes
 */
private fun sendBounce(errorCode: Int, info: MessageInfo, extraData: Map<String, String>):
        Throwable? {

    // Determine whether the sender of the original message is local to this server.
    val userEntry = withDBResult { db ->
        getEntryForTarget(db, info.sender).getOrElse {
            logError("Error getting entry for target: $it")
            return it
        }
    }.getOrElse {
        logError("Error connecting to database for entry retrieval: $it")
        return it
    } ?: run {
        return ResourceNotFoundException()
    }

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

    val userKey = userEntry.getEncryptionKey("Encryption-Key")
        ?: return BadFieldValueException("Bad encryption key from user entry")
    val sealed = Envelope.seal(userKey, msg).getOrElse { return it }
        .toStringResult().getOrElse { return it }
    val lfs = LocalFS.get()
    val handle = lfs.makeTempFile(gServerDevID, sealed.length.toLong()).getOrElse { return it }
    handle.getFile()
        .runCatching { writeText(sealed) }.onFailure { return it }
    handle.moveTo(MServerPath("/ out $gServerDevID"))?.let { return it }
    queueMessageForDelivery(gServerAddress, userAddr.domain, handle.path)

    return null
}

/**
 * Slightly higher-level database call which retrieves a list of Entry instances for a given
 * EntrySubject. This call performs no domain resolution, so if the subject is not local to the
 * server, it will return ResourceNotFound()
 */
fun getEntryForTarget(db: DBConn, subject: DeliveryTarget): Result<Entry?> {

    isDomainLocal(db, subject.domain).getOrElse {
        logError("Error determining domain ${subject.domain} is local: $it")
        return it.toFailure()
    }.onFalse {
        return KCResolver.getCurrentEntry(subject.toEntrySubject())
    }

    val rawEntries = getRawEntries(db, RandomID.fromString(subject.toString()), 0U)
        .getOrElse { return it.toFailure() }
    if (rawEntries.isEmpty()) return ResourceNotFoundException().toFailure()
    val result = if (subject.isUser()) UserEntry.fromString(rawEntries[0])
    else OrgEntry.fromString(rawEntries[0])
    val entry = result.getOrElse {
        return DatabaseCorruptionException("Bad entry received for $subject").toFailure()
    }

    return entry.toSuccess()
}

