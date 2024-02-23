package libmensago

class Platform {
    companion object {
        val isWindows = System.getProperty("os.name").startsWith("windows", true)

        fun getHostname(): Result<String> {
            // TODO: make Platform::getHostname() more robust

            val envKey = if (isWindows) "COMPUTERNAME" else "HOSTNAME"
            val env = try {
                System.getenv()
            } catch (e: Exception) {
                return Result.failure(e)
            }
            return Result.success(env[envKey]?.lowercase()?.trim() ?: "Computer name missing")
        }

        fun getUsername(): Result<String> {
            val env = try {
                System.getenv()
            } catch (e: Exception) {
                return Result.failure(e)
            }
            return Result.success(env["USERNAME"]?.trim() ?: "User name missing")
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

        fun getMakeModel(): Result<String> {
            // TODO: Implement Platform::getMakeModel()
            return Result.success("getMakeModel() unimplemented")
        }
    }
}
