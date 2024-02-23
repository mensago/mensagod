package libmensago

object Platform {
    val isWindows = System.getProperty("os.name").startsWith("windows", true)

    fun getHostname(): String {
        val envKey = if (isWindows) "COMPUTERNAME" else "HOSTNAME"
        val env = try {
            System.getenv()
        } catch (e: Exception) {
            null
        }
        if (!env?.get(envKey).isNullOrEmpty())
            return env!![envKey]!!.lowercase().trim()

        val process = try {
            Runtime.getRuntime().exec(arrayOf("hostname"))
        } catch (e: Exception) {
            return "Computer name missing"
        }
        return process.inputReader().readLine().lowercase().trim()
    }

    fun getUsername(): Result<String> {
        val env = try {
            System.getenv()
        } catch (e: Exception) {
            return Result.failure(e)
        }
        val usernameKey = if (isWindows) "USERNAME" else "USER"
        return Result.success(env[usernameKey]?.trim() ?: "User name missing")
    }

    fun getOS(): Result<String> {
        // This is a little weird because on Windows, it includes the version, as well
        val osName = try {
            System.getProperty("os.name")
        } catch (e: Exception) {
            return Result.failure(e)
        }

        if (isWindows)
            return Result.success(osName)

        val osVersion = try {
            System.getProperty("os.version")
        } catch (e: Exception) {
            return Result.failure(e)
        }

        return Result.success("$osName $osVersion")
    }
}
