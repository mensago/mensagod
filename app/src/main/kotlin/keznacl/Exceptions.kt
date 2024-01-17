package keznacl

class AlgorithmMismatchException(message: String = "") : Exception(message)
class BadValueException(message: String = "") : Exception(message)
class DecryptionFailureException : Exception()
class EmptyDataException(message: String = "") : Exception(message)
class EncryptionFailureException : Exception()
class KeyErrorException : Exception()
class ProgramException(message: String = "") : Exception(message)
class SigningFailureException : Exception()
class UnsupportedAlgorithmException(message: String = "") : Exception(message)
