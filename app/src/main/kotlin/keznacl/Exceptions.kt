package keznacl

class AlgorithmMismatchException(message: String = "") : Exception(message)
class BadValueException(message: String = "") : Exception(message)
class DecryptionFailureException(message: String = "") : Exception(message)
class EmptyDataException(message: String = "") : Exception(message)
class EncryptionFailureException(message: String = "") : Exception(message)
class KeyErrorException(message: String = "") : Exception(message)
class MissingDataException(message: String = "") : Exception(message)
class ProgramException(message: String = "") : Exception(message)
class SigningFailureException(message: String = "") : Exception(message)
class UnsupportedAlgorithmException(message: String = "") : Exception(message)
