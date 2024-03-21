package mensagod

class CancelException(message: String = "") : Exception(message)
class DatabaseException(message: String = "") : Exception(message)
class DatabaseCorruptionException(message: String = "") : Exception(message)
class ExpiredException(message: String = "") : Exception(message)
class FSFailureException(message: String = "") : Exception(message)
class UnauthorizedException(message: String = "") : Exception(message)
