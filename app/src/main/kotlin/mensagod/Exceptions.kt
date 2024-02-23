package mensagod

class CancelException(message: String = "") : Exception(message)
class DatabaseCorruptionException(message: String = "") : Exception(message)
class FSFailureException(message: String = "") : Exception(message)
