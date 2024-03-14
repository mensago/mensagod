package mensagod

import libkeycard.Timestamp
import java.io.File
import java.nio.file.Path

private var alsoStdout: Boolean = false
private var logHandle: File? = null
private val lineSep = System.lineSeparator()
private var logLevel = 2U

const val LOG_NONE: UInt = 0U
const val LOG_ERROR: UInt = 1U
const val LOG_WARN: UInt = 2U
const val LOG_INFO: UInt = 3U
const val LOG_DEBUG: UInt = 4U

/**
 * Initializes the logging system
 *
 * @throws NullPointerException if given an empty path
 */
fun initLogging(path: Path, includeStdout: Boolean) {
    alsoStdout = includeStdout
    logHandle = File(path.toString())
}

fun shutdownLogging() {
    logHandle = null
}

fun logError(msg: String) {
    if (logLevel >= LOG_ERROR) log(msg)
}

fun logWarn(msg: String) {
    if (logLevel >= LOG_WARN) log(msg)
}

fun logInfo(msg: String) {
    if (logLevel >= LOG_INFO) log(msg)
}

fun logDebug(msg: String) {
    if (logLevel >= LOG_DEBUG) log(msg)
}

/** Log function which runs regardless of application log level. */
fun log(msg: String) {
    if (msg.endsWith(lineSep)) {
        logHandle!!.appendText("${Timestamp()}: $msg")
        if (alsoStdout) print(msg)
    } else {
        logHandle!!.appendText("${Timestamp()}: $msg$lineSep")
        if (alsoStdout) println(msg)
    }
}

/** Returns the current logging level */
fun getLogLevel(): UInt {
    return logLevel
}

/** Sets the logging level. System default is logging errors and warnings. */
fun setLogLevel(level: UInt) {
    logLevel = level
}
