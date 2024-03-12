package mensagod

class UnauthorizedException(message: String = "") : Exception(message)
class CancelException(message: String = "") : Exception(message)
class DatabaseCorruptionException(message: String = "") : Exception(message)
class FSFailureException(message: String = "") : Exception(message)
