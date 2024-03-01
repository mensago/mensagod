package libmensago.resolver

import libkeycard.Domain
import libmensago.ServiceConfig
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** The ServiceCache holds getRemoteServerConfig() results */
class ServiceCache(capacity: Int) {

    private val queue = LinkedBlockingQueue<ServiceNode>(capacity)
    private val lock = ReentrantLock()

    fun get(dom: Domain): List<ServiceConfig>? {
        return lock.withLock {
            find(dom)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.list
    }

    fun put(dom: Domain, list: List<ServiceConfig>) {
        lock.withLock {
            val node = ServiceNode(dom.hashCode(), list)
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

    private fun find(dom: Domain): ServiceNode? {
        val hash = dom.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class ServiceNode(val hash: Int, val list: List<ServiceConfig>) {
    override fun toString(): String {
        return "{${list.joinToString("")}}"
    }
}
