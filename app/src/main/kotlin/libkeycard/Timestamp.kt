package libkeycard

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.regex.Pattern

@Serializable(with = TimestampSerializer::class)
class Timestamp(i: Instant? = null) {
    var value: Instant = i ?: Instant.now().let { it.minusNanos(it.nano.toLong()) }
        private set
    var formatted: String = DateTimeFormatter.ISO_INSTANT.format(value)
        private set

    fun set(reqValue: Instant): Timestamp {
        value = reqValue.let { it.minusNanos(it.nano.toLong()) }
        formatted = DateTimeFormatter.ISO_INSTANT.format(value)
        return this
    }

    /**
     * Returns the object as a string with just the date in the format YYMMDD.
     */
    fun toDateString(): String {
        return dateFormatter.format(value)
    }

    override fun toString(): String {
        return formatted
    }

    /**
     * Returns a copy of the current instance offset by the specified number of days into the
     * future, if positive, or the past, if negative.
     */
    fun plusDays(days: Int): Timestamp {
        return Timestamp().set(value.plusSeconds(days.toLong() * 86400))
    }

    /**
     * Returns a copy of the current instance offset by the specified number of hours into the
     * future, if positive, or the past, if negative.
     */
    fun plusHours(hours: Int): Timestamp {
        return Timestamp().set(value.plusSeconds(hours.toLong() * 3600))
    }

    /**
     * Returns a copy of the current instance offset by the specified number of minutes into the
     * future, if positive, or the past, if negative.
     */
    fun plusMinutes(minutes: Int): Timestamp {
        return Timestamp().set(value.plusSeconds(minutes.toLong() * 60))
    }

    /** Returns true if the value in the object is later than the timestamp passed to it */
    fun isAfter(other: Timestamp): Boolean {
        return value > other.value
    }

    /** Returns true if the value in the object is earlier than the timestamp passed to it */
    fun isBefore(other: Timestamp): Boolean {
        return value < other.value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Timestamp
        return value == other.value
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }

    companion object {
        private val dateTimePattern = Pattern.compile(
            """\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z)"""
        )
        private val dateFormatter =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC)!!

        /** Returns true if the supplied data matches the expected data format */
        fun checkFormat(value: String): Boolean {
            return dateTimePattern.matcher(value).matches()
        }


        /**
         * Creates an instance from a string in the format YYYY-MM-DDThh:mm:ssZ
         */
        fun fromString(str: String?): Timestamp? {
            if (str == null) return null
            return try {
                Timestamp().set(Instant.parse(str))
            } catch (e: Exception) {
                return null
            }
        }

        /**
         * Creates a Timestamp object from just a date, which is stored internally as midnight on
         * that date.
         */
        fun fromDateString(s: String?): Timestamp? {
            if (s == null) return null
            val date = try {
                LocalDate.parse(s, dateFormatter).atStartOfDay()
            } catch (e: Exception) {
                return null
            }
            val instant = date.atZone(ZoneId.of("UTC")).toInstant()
            return Timestamp().set(instant)
        }

        /**
         * Creates a new Timestamp object using the current time plus the specified number of days
         * into the future, if positive, or the past, if negative.
         */
        fun plusDays(days: Int): Timestamp {
            return Timestamp().set(Instant.now().plusSeconds(days.toLong() * 86400))
        }

    }
}

object TimestampSerializer : KSerializer<Timestamp> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Timestamp", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Timestamp) {
        encoder.encodeString(value.value.toString())
    }

    override fun deserialize(decoder: Decoder): Timestamp {
        return Timestamp(Instant.parse(decoder.decodeString()))
    }
}
