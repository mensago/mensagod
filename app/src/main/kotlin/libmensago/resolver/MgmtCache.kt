package libmensago.resolver

import libkeycard.Domain
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** The MgmtCache holds getMgmtRecord() results */
class MgmtCache(capacity: Int) {

    private val queue = LinkedBlockingQueue<MgmtNode>(capacity)
    private val lock = ReentrantLock()

    fun get(dom: Domain): DNSMgmtRecord? {
        return lock.withLock {
            find(dom)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.rec
    }

    fun put(dom: Domain, rec: DNSMgmtRecord) {
        lock.withLock {
            val node = MgmtNode(dom.hashCode(), rec)
            if (queue.remainingCapacity() == 0)
                queue.remove()
            queue.add(node)
        }
    }

    /**
     * Debugging function to return the current state of the queue.
     */
    fun debugState(): String {
        return lock.withLock {
            queue.joinToString("\n")
        }
    }

    private fun find(dom: Domain): MgmtNode? {
        val hash = dom.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class MgmtNode(val hash: Int, val rec: DNSMgmtRecord) {
    override fun toString(): String {
        return rec.toString()
    }
}
