package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import org.kotlincrypto.hash.sha2.SHA256

// Safety numbers for manual identity verification, see
// docs/identity-verification.md. They cover the messaging identity keys
// only, never device authentication, prekey, session or storage keys.

/**
 * The public messaging identity key of a device: [SIZE] bytes (X25519 key
 * followed by Ed25519 key), as in a prekey bundle. Immutable: the bytes are
 * copied in and out.
 */
class PublicIdentityKey(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Identity key must have $SIZE bytes" }
    }

    /** A copy of the key bytes. */
    val bytes: ByteArray get() = value.copyOf()

    /** Compares with raw key bytes without copying them. */
    fun contentEquals(other: ByteArray): Boolean = value.contentEquals(other)

    override fun equals(other: Any?): Boolean = other is PublicIdentityKey && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "PublicIdentityKey($SIZE bytes)"

    companion object {
        const val SIZE: Int = ProtocolConstants.PUBLIC_KEY_SIZE
    }
}

/** Whether the user confirmed a pinned remote identity out of band (docs/identity-verification.md). */
enum class VerificationState {
    /** Trusted on first use or accepted as a change, not compared by the user. */
    UNVERIFIED,

    /** The user compared the safety number of exactly this pinned key and confirmed it. */
    VERIFIED,
}

/** The raw safety number: SHA-256 over both devices' addresses and identity keys, [SIZE] bytes. */
class SafetyFingerprint(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Safety fingerprint must have $SIZE bytes" }
    }

    /** A copy of the fingerprint bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is SafetyFingerprint && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "SafetyFingerprint(${SafetyNumber.display(value)})"

    companion object {
        const val SIZE: Int = 32
    }
}

/** Result of comparing a local [SafetyNumber] with one scanned from the other device. */
enum class SafetyNumberComparison {
    /** Same two devices, same fingerprint: the identity keys match. */
    MATCH,

    /** Same two devices, different fingerprint: at least one side has another identity key. */
    MISMATCH,

    /** The payload is about another pair of devices (wrong contact or device scanned). */
    DIFFERENT_DEVICES,
}

/**
 * Safety number version 1 of two devices (docs/identity-verification.md).
 *
 * The fingerprint is SHA-256 over
 *
 * ```
 * u32 length | domain (UTF-8, "KSecureMessage-SafetyNumber-v1")
 * | u32 length | first userId (UTF-8)  | u32 length | first deviceId (UTF-8)  | first identity key (64)
 * | u32 length | second userId (UTF-8) | u32 length | second deviceId (UTF-8) | second identity key (64)
 * ```
 *
 * with big-endian integers. [first] is the device whose address encoding
 * (`u32 length | userId | u32 length | deviceId`) is smaller, compared
 * unsigned-lexicographically, so both devices derive the same value no matter
 * who asks. Each identity key stays tied to its own address.
 *
 * [displayString] is the human-comparable form: 12 groups of 5 decimal
 * digits. [encode] is the machine-readable form for a QR code or similar,
 * see [SafetyNumberCodec]. Neither contains key material.
 */
class SafetyNumber private constructor(
    val first: DeviceAddress,
    val second: DeviceAddress,
    val fingerprint: SafetyFingerprint,
) {
    /** The 12 groups of 5 digits of [displayString]. */
    val groups: List<String> get() = groups(fingerprint.bytes)

    /** 60 decimal digits in 12 groups of 5, separated by single spaces. Locale independent. */
    val displayString: String get() = display(fingerprint.bytes)

    /** The machine-readable payload, version 1 ([SafetyNumberCodec]). A fresh array on every call. */
    fun encode(): ByteArray = SafetyNumberCodec.encode(SafetyNumberPayload(first, second, fingerprint))

    /** Compares with the payload the other device shows. Changes nothing, verifies nothing by itself. */
    fun compare(scanned: SafetyNumberPayload): SafetyNumberComparison = when {
        scanned.first != first || scanned.second != second -> SafetyNumberComparison.DIFFERENT_DEVICES
        scanned.fingerprint != fingerprint -> SafetyNumberComparison.MISMATCH
        else -> SafetyNumberComparison.MATCH
    }

    override fun equals(other: Any?): Boolean =
        other is SafetyNumber && first == other.first && second == other.second && fingerprint == other.fingerprint

    override fun hashCode(): Int = (first.hashCode() * 31 + second.hashCode()) * 31 + fingerprint.hashCode()

    override fun toString(): String = "SafetyNumber($first, $second, $displayString)"

    companion object {
        const val GROUP_COUNT: Int = 12
        const val GROUP_DIGITS: Int = 5
        private const val BLOCK_BYTES = 5
        private const val CHUNK_BITS = 20
        private const val CHUNK_MASK = (1L shl CHUNK_BITS) - 1
        private const val GROUP_MODULUS = 100_000L

        /**
         * The safety number of [localAddress] with [localIdentityKey] and
         * [remoteAddress] with [remoteIdentityKey]. Swapping the two sides
         * gives the same result. Throws [IllegalArgumentException] for two
         * equal addresses or an address that is not valid Unicode.
         */
        fun derive(
            localAddress: DeviceAddress,
            localIdentityKey: PublicIdentityKey,
            remoteAddress: DeviceAddress,
            remoteIdentityKey: PublicIdentityKey,
        ): SafetyNumber {
            require(localAddress != remoteAddress) { "A safety number needs two different devices" }
            val local = encodeAddress(localAddress)
            val remote = encodeAddress(remoteAddress)
            val localFirst = compareUnsigned(local, remote) < 0
            val out = BinaryWriter()
            out.bytes(DOMAIN)
            if (localFirst) {
                out.fixed(local)
                out.fixed(localIdentityKey.bytes)
                out.fixed(remote)
                out.fixed(remoteIdentityKey.bytes)
            } else {
                out.fixed(remote)
                out.fixed(remoteIdentityKey.bytes)
                out.fixed(local)
                out.fixed(localIdentityKey.bytes)
            }
            val fingerprint = SafetyFingerprint(SHA256().digest(out.toByteArray()))
            return if (localFirst) {
                SafetyNumber(localAddress, remoteAddress, fingerprint)
            } else {
                SafetyNumber(remoteAddress, localAddress, fingerprint)
            }
        }

        /** `u32 length | userId (UTF-8) | u32 length | deviceId (UTF-8)`. */
        internal fun encodeAddress(address: DeviceAddress): ByteArray {
            val out = BinaryWriter()
            out.bytes(utf8(address.userId.value))
            out.bytes(utf8(address.deviceId.value))
            return out.toByteArray()
        }

        /** Unsigned lexicographic order; a proper prefix sorts first. */
        internal fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val result = (a[i].toInt() and 0xFF).compareTo(b[i].toInt() and 0xFF)
                if (result != 0) return result
            }
            return a.size.compareTo(b.size)
        }

        /**
         * Bytes 0..29 of [fingerprint] (240 bits) as 12 big-endian chunks of
         * 20 bits; each chunk is reduced modulo 100000 and written with 5
         * digits, zero-padded. Two chunks come from each 5-byte block, read
         * as a 40-bit integer. Plain [Long] arithmetic, identical on every
         * target.
         */
        internal fun groups(fingerprint: ByteArray): List<String> = List(GROUP_COUNT) { group ->
            val block = group / 2
            var value = 0L
            for (i in 0 until BLOCK_BYTES) value = (value shl 8) or (fingerprint[block * BLOCK_BYTES + i].toLong() and 0xFF)
            val chunk = if (group % 2 == 0) value ushr CHUNK_BITS else value and CHUNK_MASK
            (chunk % GROUP_MODULUS).toString().padStart(GROUP_DIGITS, '0')
        }

        internal fun display(fingerprint: ByteArray): String = groups(fingerprint).joinToString(" ")

        private fun utf8(value: String): ByteArray {
            val bytes = value.encodeToByteArray()
            // encodeToByteArray replaces lone surrogates, which would let two addresses encode alike.
            require(bytes.decodeToString() == value) { "Address is not valid Unicode" }
            return bytes
        }

        private val DOMAIN = ProtocolConstants.SAFETY_NUMBER_DOMAIN.encodeToByteArray()
    }
}

/**
 * A decoded verification payload: the two devices in canonical order and
 * their fingerprint. Decoding proves nothing; compare it with
 * [SafetyNumber.compare].
 */
class SafetyNumberPayload(
    val first: DeviceAddress,
    val second: DeviceAddress,
    val fingerprint: SafetyFingerprint,
) {
    override fun toString(): String = "SafetyNumberPayload($first, $second)"
}

/**
 * Machine-readable safety number payload, version 1, for a QR code or any
 * other channel the application picks. Both devices produce identical bytes.
 *
 * ```
 * version:u8 = 1
 * | u32 length | first userId (UTF-8)  | u32 length | first deviceId (UTF-8)
 * | u32 length | second userId (UTF-8) | u32 length | second deviceId (UTF-8)
 * | fingerprint (32)
 * ```
 *
 * Holds no key material. Decoding is strict (version, valid UTF-8, canonical
 * address order, exact sizes, no trailing bytes) and throws
 * [IllegalArgumentException] otherwise.
 */
object SafetyNumberCodec {
    private const val VERSION: Byte = 1

    fun encode(payload: SafetyNumberPayload): ByteArray {
        val out = BinaryWriter()
        out.byte(VERSION)
        out.fixed(SafetyNumber.encodeAddress(payload.first))
        out.fixed(SafetyNumber.encodeAddress(payload.second))
        out.fixed(payload.fingerprint.bytes)
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): SafetyNumberPayload {
        val reader = BinaryReader(bytes)
        require(reader.byte() == VERSION) { "Unsupported safety number format" }
        val first = reader.address()
        val second = reader.address()
        require(SafetyNumber.compareUnsigned(SafetyNumber.encodeAddress(first), SafetyNumber.encodeAddress(second)) < 0) {
            "Devices are not in canonical order"
        }
        val fingerprint = SafetyFingerprint(reader.fixed(SafetyFingerprint.SIZE))
        reader.requireEnd()
        return SafetyNumberPayload(first, second, fingerprint)
    }

    private fun BinaryReader.address(): DeviceAddress = DeviceAddress(UserId(utf8()), DeviceId(utf8()))

    private fun BinaryReader.utf8(): String {
        val bytes = bytes()
        val value = bytes.decodeToString()
        // decodeToString replaces malformed sequences; a lossless round trip means valid UTF-8.
        require(value.encodeToByteArray().contentEquals(bytes)) { "Invalid UTF-8" }
        return value
    }
}
