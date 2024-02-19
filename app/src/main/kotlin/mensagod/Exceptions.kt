package mensagod

class DatabaseCorruptionException(message: String = ""): Exception(message)
class FSFailureException(message: String = ""): Exception(message)
