package keznacl

/**
 * Wraps the parent value in Result.success()
 */
inline fun <reified T> T.toSuccess(): Result<T> {
    return Result.success(this)
}

/**
 * Wraps the parent Throwable in Result.failure()
 */
inline fun <reified T> Throwable.toFailure(): Result<T> {
    return Result.failure(this)
}

/**
 * Executes the code block if the Boolean value is true
 */
inline fun Boolean.onTrue(block: () -> Unit) {
    if (this)
        block()
}

/**
 * Executes the code block if the Boolean value is true
 */
inline fun Boolean.onFalse(block: () -> Unit) {
    if (!this)
        block()
}

/**
 * Executes the code block if the string is empty or null
 */
inline fun CharSequence?.onNullOrEmpty(block: () -> Unit) {
    if (this.isNullOrEmpty())
        block()
}
