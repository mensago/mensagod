package libmensago

inline fun <reified T> T.toSuccess(): Result<T> {
    return Result.success(this)
}

inline fun <reified T> Throwable.toFailure(): Result<T> {
    return Result.failure(this)
}
