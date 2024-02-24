package libmensago

class BadFrameException(message: String = "") : Exception(message)
class BadSessionException(message: String = "") : Exception(message)
class DNSException(message: String = "") : Exception(message)
class InvalidPathException(message: String = "") : Exception(message)
class InsufficientResourceException(message: String = "") : Exception(message)
class NotConnectedException(message: String = "") : Exception(message)
class NetworkErrorException(message: String = "") : Exception(message)
class ResourceExistsException(message: String = "") : Exception(message)
class ResourceNotFoundException(message: String = "") : Exception(message)
class SchemaFailureException(message: String = "") : Exception(message)
class ServerAuthException : Exception()
class SizeException(message: String = "") : Exception(message)
class TypeException(message: String = "") : Exception(message)
class ServerException(message: String = "") : Exception(message)

class ProtocolException(cmdStatus: CmdStatus) : Exception(cmdStatus.toString()) {
    val code = cmdStatus.code
    val description = cmdStatus.description
    val info = cmdStatus.info
}
