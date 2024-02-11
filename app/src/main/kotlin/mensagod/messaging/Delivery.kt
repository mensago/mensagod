package mensagod.messaging

import mensagod.MServerPath
import mensagod.WorkerPool
import java.util.concurrent.SynchronousQueue

/**
 * Used for giving the necessary information for delivery threads to do their jobs.
 */
class MessageInfo(val sender: String, val receiver: String, path: MServerPath)

// The global message queue for delivery threads to process work from.
private val gMessageQueue = SynchronousQueue<MessageInfo>()
private val gDeliveryPool = WorkerPool(100)

/**
 * Add a MessageInfo object to the delivery queue. It also spawns a delivery thread to handle the
 * message if the thread pool is not running at capacity.
 */
fun queueMessageForDelivery(info: MessageInfo) {
    gMessageQueue.put(info)

    // TODO: Launch delivery thread
}

fun deliveryWorker(id: ULong) {

    while (!gDeliveryPool.isQuitting()) {
        // TODO: Finish deliveryWorker()
        break
    }

    gDeliveryPool.done(id)
}
