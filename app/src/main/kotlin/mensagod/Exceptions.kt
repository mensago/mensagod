package mensagod

class BadFrameException(message: String = ""): Exception(message)
class BadSessionException(message: String = ""): Exception(message)
class DatabaseCorruptionException(message: String = ""): Exception(message)
class FSFailureException(message: String = ""): Exception(message)
class FrameTypeException(message: String = ""): Exception(message)
class InvalidPathException(message: String = ""): Exception(message)
class NotConnectedException(message: String = ""): Exception(message)
class NetworkErrorException(message: String = ""): Exception(message)
class ResourceExistsException(message: String = ""): Exception(message)
class ResourceNotFoundException(message: String = ""): Exception(message)
class SizeException(message: String = ""): Exception(message)
class TypeException(message: String = ""): Exception(message)