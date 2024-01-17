package libkeycard

class BadFieldException(message: String? = null) : Exception(message)
class BadFieldValueException(message: String? = null) : Exception(message)
class ComplianceFailureException(message: String? = null) : Exception(message)
class EntryTypeException: Exception()
class HashMismatchException: Exception()
class InvalidKeycardException(message: String? = null) : Exception(message)
class MissingDataException(message: String? = null) : Exception(message)
class MissingFieldException(message: String? = null) : Exception(message)
class OutOfOrderException(message: String? = null) : Exception(message)
class RangeException(message: String? = null) : Exception(message)
class RevokedEntryException: Exception()
