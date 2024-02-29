package libmensago.resolver

import libkeycard.Entry
import libmensago.EntrySubject
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** The EntryCache holds getCurrentEntry() results */
class EntryCache(capacity: Int) {

    private val queue = LinkedBlockingQueue<EntryNode>(capacity)
    private val lock = ReentrantLock()

    fun get(subject: EntrySubject): Entry? {
        return lock.withLock {
            find(subject)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.entry
    }

    fun put(entry: Entry) {
        lock.withLock {
            val node = EntryNode.new(entry)
            if (node != null) {
                if (queue.remainingCapacity() == 0)
                    queue.remove()
                queue.add(node)
            }

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

    private fun find(subject: EntrySubject): EntryNode? {
        val hash = subject.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class EntryNode(val hash: Int, val entry: Entry) {

    override fun toString(): String {
        val node = EntrySubject.fromEntry(entry)
        return node?.toString() ?: "null"
    }

    companion object {
        fun new(entry: Entry): EntryNode? {
            val sub = EntrySubject.fromEntry(entry) ?: return null
            return EntryNode(sub.hashCode(), entry)
        }
    }
}
