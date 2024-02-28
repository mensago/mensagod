package libmensago.cache

import libkeycard.Entry

/**
 * The EntryCache interface is for classes which implement some kind of caching of keycard entries.
 */
interface EntryCache {
    fun put(e: Entry): Throwable?
    fun get(subject: EntrySubject): Result<Entry>
    fun remove(subject: EntrySubject)
}

/**
 * The EntryMemCache class caches keycard entries in memory
 */
class EntryMemCache(var size: Int) {
    fun put(e: Entry): Throwable? {
        TODO("Implement EntryMemCache::put")
    }

    fun get(subject: EntrySubject): Result<Entry> {
        TODO("Implement EntryMemCache::get")
    }

    fun remove(subject: EntrySubject) {
        TODO("Implement EntryMemCache::remove")
    }
}
