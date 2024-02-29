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
            find(subject)
        }?.entry
    }

    fun put(entry: Entry) {
        lock.withLock {
            val node = EntryNode.new(entry)
            if (node != null)
                queue.add(node)
        }
    }

    fun remove(subject: EntrySubject) {
        lock.withLock {
            find(subject)?.let { queue.remove(it) }
        }
    }

    fun removeItem(entry: Entry) {
        lock.withLock {
            val node = EntryNode.new(entry)
            if (node != null)
                queue.removeIf { it.hash == node.hash }
        }
    }

    private fun find(subject: EntrySubject): EntryNode? {
        val hash = subject.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class EntryNode(val hash: Int, val entry: Entry) {

    companion object {
        fun new(entry: Entry): EntryNode? {
            val sub = EntrySubject.fromEntry(entry) ?: return null
            return EntryNode(sub.hashCode(), entry)
        }
    }
}
