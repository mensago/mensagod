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

