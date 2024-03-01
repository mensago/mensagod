package libmensago.resolver

import libkeycard.MAddress
import libkeycard.RandomID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** The WIDCache holds resolveMenagoAddress() results */
class WIDCache(capacity: Int) {

    private val queue = LinkedBlockingQueue<WIDNode>(capacity)
    private val lock = ReentrantLock()

    fun get(maddr: MAddress): RandomID? {
        return lock.withLock {
            find(maddr)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.id
    }

    fun put(maddr: MAddress, id: RandomID) {
        lock.withLock {
            val node = WIDNode(maddr.hashCode(), id)
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

    private fun find(maddr: MAddress): WIDNode? {
        val hash = maddr.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class WIDNode(val hash: Int, val id: RandomID) {
    override fun toString(): String {
        return id.toString()
    }
}
