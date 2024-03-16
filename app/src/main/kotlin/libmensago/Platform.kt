package libmensago

import keznacl.toFailure

object Platform {
    val isWindows = System.getProperty("os.name").startsWith("windows", true)

    fun getHostname(): String {
        val envKey = if (isWindows) "COMPUTERNAME" else "HOSTNAME"
        val env = runCatching {
            System.getenv()
        }.getOrElse { null }
        if (!env?.get(envKey).isNullOrEmpty())
            return env!![envKey]!!.lowercase().trim()

        val process = runCatching {
            Runtime.getRuntime().exec(arrayOf("hostname"))
        }.getOrElse {
            return "Computer name missing"
        }
        return process.inputReader().readLine().lowercase().trim()
    }

    fun getUsername(): Result<String> {
        val env = runCatching { System.getenv() }
            .getOrElse { return it.toFailure() }
        val usernameKey = if (isWindows) "USERNAME" else "USER"
        return Result.success(env[usernameKey]?.trim() ?: "User name missing")
    }

    fun getOS(): Result<String> {
        // This is a little weird because on Windows, it includes the version, as well
        val osName = runCatching { System.getProperty("os.name") }
            .getOrElse { return it.toFailure() }

        if (isWindows)
            return Result.success(osName)

        val osVersion = runCatching { System.getProperty("os.version") }
            .getOrElse { return it.toFailure() }

        return Result.success("$osName $osVersion")
    }
}
