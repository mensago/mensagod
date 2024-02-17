package libmensago

class ServerException(message: String = "") : Exception(message)

class ProtocolException(cmdStatus: CmdStatus): Exception(cmdStatus.toString()) {
    val code = cmdStatus.code
    val description = cmdStatus.description
    val info = cmdStatus.info
}
