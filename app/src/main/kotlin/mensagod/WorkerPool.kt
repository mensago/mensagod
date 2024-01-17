package mensagod

class WorkerPool(var capacity: Int = 100) {
    private var currentID = 0UL
    private val workers = mutableSetOf<ULong>()
    private var quitFlag = false

    /**
     * Launch a new worker ID to the pool. If the pool is at or over capacity, it will return null.
     */
    fun add(): ULong? {
        synchronized(this) {
            if (workers.size >= capacity) return null

            currentID++
            return currentID
        }
    }

    /** Returns the number of workers running */
    fun count(): Int {
        synchronized(this) {
            return workers.size
        }
    }

    /** done() is called by workers to signify they are quitting */
    fun done(id: ULong) {
        synchronized(this) {
            workers.remove(id)
        }
    }

    /**
     * Returns true if the number of workers is greater than or equal to the pool's current
     * capacity.
     */
    fun isFull(): Boolean {
        synchronized(this) {
            return workers.size >= capacity
        }
    }

    /** Returns true if the ID is in the list of running workers */
    fun isQuitting(): Boolean {
        synchronized(this) {
            return quitFlag
        }
    }

    /** Returns true if the ID is in the list of running workers */
    fun isRunning(id: ULong): Boolean {
        synchronized(this) {
            return workers.contains(id)
        }
    }

    /** Signal to all workers that we are quitting */
    fun quit() {
        synchronized(this) {
            quitFlag = true
        }
    }

    /** waits for all workers to quit */
    fun waitForClients() {
        while (true) {
            if (workers.isEmpty())
                break
            Thread.sleep(25)
        }
    }
}

