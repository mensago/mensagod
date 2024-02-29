package libmensago.resolver

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class LookupCache<T>(capacity: Int) {

    private val queue = LinkedBlockingQueue<LookupNode<T>>(capacity)
    private val lock = ReentrantLock()

    fun get(id: Any): T? {
        return lock.withLock {
            find(id)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.entry
    }

    fun put(node: LookupNode<T>, entry: T) {
        lock.withLock {
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

    private fun find(subject: Any): LookupNode<T>? {
        val hash = subject.hashCode()
        return queue.find { it.hash == hash }
    }
}

class LookupNode<T>(val hash: Int, val entry: T)
