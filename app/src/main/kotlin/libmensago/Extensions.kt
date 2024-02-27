package libmensago

import java.nio.file.Path
import java.nio.file.Paths

inline fun <reified T> T.toSuccess(): Result<T> {
    return Result.success(this)
}

inline fun <reified T> Throwable.toFailure(): Result<T> {
    return Result.failure(this)
}

fun List<String>.toPath(): Path {
    return if (this.size == 1)
        Paths.get(this[0])
    else
        Paths.get(this[0], *this.subList(1, this.size).toTypedArray())
}
