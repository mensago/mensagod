package libmensago.resolver

import libkeycard.Keycard
import libmensago.EntrySubject
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class KeycardCache(capacity: Int) {

    private val queue = LinkedBlockingQueue<KeycardNode>(capacity)
    private val lock = ReentrantLock()

    fun get(subject: EntrySubject): Keycard? {
        return lock.withLock {
            find(subject)?.let {
                queue.remove(it)
                queue.add(it)
                it
            }
        }?.keycard
    }

    fun put(keycard: Keycard) {
        lock.withLock {
            val node = KeycardNode.new(keycard)
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

    private fun find(subject: EntrySubject): KeycardNode? {
        val hash = subject.hashCode()
        return queue.find { it.hash == hash }
    }
}

private class KeycardNode(val hash: Int, val keycard: Keycard) {

    override fun toString(): String {
        val node = EntrySubject.fromEntry(keycard.current ?: return "null")
        return node?.toString() ?: "null"
    }

    companion object {
        fun new(keycard: Keycard): KeycardNode? {
            if (keycard.entries.size == 0) return null
            val sub = EntrySubject.fromEntry(keycard.current!!) ?: return null
            return KeycardNode(sub.hashCode(), keycard)
        }
    }
}

