package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.UserId
import io.kodium.Kodium
import io.kodium.KodiumPrivateKey
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.time.Instant
import kotlin.uuid.Uuid

// Device authentication to the KSecureMessage server (docs/server-authentication.md).
// A separate Ed25519 key from the messaging identity key: it only proves to the
// server that a request comes from the device registered for an address.

/**
 * The local device's authentication key pair: a 32-byte Ed25519 seed and the
 * 32-byte Ed25519 public key. Created by [ProtocolEngine.createDeviceAuthenticationKey].
 * The private key never leaves the device; the server only gets [publicKey].
 * A plain class, so toString() never prints key bytes.
 */
class DeviceAuthenticationKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
) {
    override fun toString(): String = "DeviceAuthenticationKeyPair(privateKey=<redacted>)"
}

/**
 * Single-use value of one authenticated request: [SIZE] random bytes. The
 * server accepts each nonce once per device within the validity window.
 */
class RequestNonce(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Request nonce must have $SIZE bytes" }
    }

    /** A copy of the nonce bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is RequestNonce && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RequestNonce(<redacted>)"

    companion object {
        const val SIZE: Int = 16

        /** 16 bytes from the platform's cryptographically secure generator (as [Uuid.random], 122 random bits). */
        fun random(): RequestNonce = RequestNonce(Uuid.random().toByteArray())
    }
}

/**
 * What an authenticated request is about: the device it acts for, the HTTP
 * [method], the canonical [path] ([ServerApiPaths]) and the exact bytes of
 * the HTTP request [body] (empty for a request without body).
 */
class ServerRequest(
    val address: DeviceAddress,
    val method: String,
    val path: String,
    val body: ByteArray,
) {
    override fun toString(): String = "ServerRequest($method $path)"
}

/**
 * The authentication a device attaches to a [ServerRequest]: when it was
 * made (epoch milliseconds, no finer), a fresh nonce and the Ed25519
 * signature over [ServerRequestAuthentication.canonicalInput].
 */
class RequestAuthentication(
    val timestamp: Instant,
    val nonce: RequestNonce,
    signature: ByteArray,
) {
    private val value: ByteArray = signature.copyOf()

    init {
        require(timestamp.toEpochMilliseconds() >= 0) { "Timestamp must not be before the epoch" }
        require(Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds()) == timestamp) {
            "Timestamp must be whole milliseconds"
        }
    }

    /** A copy of the signature bytes. */
    val signature: ByteArray get() = value.copyOf()

    override fun toString(): String = "RequestAuthentication(timestamp=$timestamp, nonce=<redacted>, signature=<redacted>)"
}

/**
 * Canonical paths of the device-scoped HTTP API v1. The client builds its
 * request URLs from them; the server rebuilds them from the decoded route
 * parameters. Signatures cover these paths, never a raw request URI.
 *
 * Each address component is one path segment, percent-encoded as in RFC
 * 3986: the unreserved characters `A-Z a-z 0-9 - . _ ~` stay as they are,
 * every other UTF-8 byte becomes `%XX` with upper-case hex digits.
 */
object ServerApiPaths {
    const val REGISTRATION: String = "registration"
    const val PRE_KEYS: String = "prekeys"
    const val PRE_KEY_BUNDLE: String = "prekey-bundle"
    const val MESSAGES: String = "messages"

    /** Device recovery (docs/device-recovery.md). Not a ServerAuth-signed endpoint. */
    const val REGISTRATION_RECOVERY: String = "registration/recovery"

    /** Routine device authentication key rotation (docs/device-authentication-rotation.md). Not a ServerAuth-signed endpoint. */
    const val REGISTRATION_ROTATION: String = "registration/rotation"

    /** Last-device recovery (docs/last-device-recovery.md). Not a ServerAuth-signed endpoint. */
    const val LAST_DEVICE_RECOVERY: String = "last-device-recovery"

    /** Issues a last-device recovery challenge. Public, not ServerAuth-signed. */
    const val LAST_DEVICE_RECOVERY_CHALLENGE: String = "last-device-recovery/challenge"

    /** Registers the user's last-device recovery key. ServerAuth-signed. */
    const val LAST_DEVICE_RECOVERY_KEY: String = "last-device-recovery/key"

    /**
     * Rotates the user's last-device recovery key (docs/recovery-key-lifecycle.md).
     * ServerAuth-signed; the body carries the current recovery key's signature.
     */
    const val LAST_DEVICE_RECOVERY_KEY_ROTATION: String = "last-device-recovery/key/rotation"

    /**
     * Revokes the user's last-device recovery key (docs/recovery-key-lifecycle.md).
     * ServerAuth-signed; the body carries the current recovery key's signature.
     */
    const val LAST_DEVICE_RECOVERY_KEY_REVOCATION: String = "last-device-recovery/key/revocation"

    /**
     * Requests (`PUT`) or reads (`GET`) the user's delayed recovery key reset
     * (docs/recovery-key-reset.md). ServerAuth-signed.
     */
    const val LAST_DEVICE_RECOVERY_KEY_RESET: String = "last-device-recovery/key/reset"

    /** Completes a pending recovery key reset. ServerAuth-signed; the body carries the new key's proof of possession. */
    const val LAST_DEVICE_RECOVERY_KEY_RESET_COMPLETION: String = "last-device-recovery/key/reset/completion"

    /**
     * Cancels a pending recovery key reset. Device-scoped: ServerAuth-signed.
     * User-scoped ([user]): public, the body carries the current recovery
     * key's signature.
     */
    const val LAST_DEVICE_RECOVERY_KEY_RESET_CANCELLATION: String = "last-device-recovery/key/reset/cancellation"

    /**
     * User-scoped recovery key reset status query ([user]). Public, not
     * ServerAuth-signed: the body carries the current recovery key's signature.
     */
    const val LAST_DEVICE_RECOVERY_KEY_RESET_STATUS: String = "last-device-recovery/key/reset/status"

    /** `/v1/devices/{user}/{device}/{endpoint}`. */
    fun device(address: DeviceAddress, endpoint: String): String =
        "/v1/devices/${encodeSegment(address.userId.value)}/${encodeSegment(address.deviceId.value)}/$endpoint"

    /**
     * `/v1/users/{user}/{endpoint}`: the routes an offline recovery key holder
     * uses without any device (docs/recovery-key-reset.md). Never ServerAuth-signed.
     */
    fun user(userId: UserId, endpoint: String): String = "/v1/users/${encodeSegment(userId.value)}/$endpoint"

    fun encodeSegment(value: String): String = buildString {
        for (byte in value.encodeToByteArray()) {
            val c = (byte.toInt() and 0xFF).toChar()
            if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '.' || c == '_' || c == '~') {
                append(c)
            } else {
                append('%')
                append(HEX[(byte.toInt() shr 4) and 0xF])
                append(HEX[byte.toInt() and 0xF])
            }
        }
    }

    private const val HEX = "0123456789ABCDEF"
}

/**
 * Signs and verifies server requests with a device authentication key,
 * format version 1 (docs/server-authentication.md). The signed input is:
 *
 * ```
 * u32 length | "KSecureMessage-ServerAuth-v1" (UTF-8)
 * u32 length | userId (UTF-8) | u32 length | deviceId (UTF-8)
 * u32 length | method (ASCII, upper case)
 * u32 length | canonical path (UTF-8)
 * SHA-256(body) (32)
 * timestamp: i64, epoch milliseconds
 * nonce (16)
 * ```
 *
 * Integers are big-endian. The signature is Ed25519 over the whole input.
 * The domain string keeps signatures made for anything else (signed
 * prekeys, other protocols) from verifying as a request signature.
 */
object ServerRequestAuthentication {
    /** Size of a device authentication public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a request signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /**
     * The bytes the signature covers. Throws [IllegalArgumentException] for a
     * method that is not upper-case ASCII letters.
     */
    fun canonicalInput(request: ServerRequest, timestamp: Instant, nonce: RequestNonce): ByteArray {
        require(request.method.isNotEmpty() && request.method.all { it in 'A'..'Z' }) { "Invalid HTTP method" }
        val out = BinaryWriter()
        out.bytes(DOMAIN)
        out.bytes(request.address.userId.value.encodeToByteArray())
        out.bytes(request.address.deviceId.value.encodeToByteArray())
        out.bytes(request.method.encodeToByteArray())
        out.bytes(request.path.encodeToByteArray())
        out.fixed(SHA256().digest(request.body))
        out.long(timestamp.toEpochMilliseconds())
        out.fixed(nonce.bytes)
        return out.toByteArray()
    }

    /** Authenticates [request] at [timestamp] (truncated to milliseconds) with a fresh [nonce]. */
    fun sign(
        keyPair: DeviceAuthenticationKeyPair,
        request: ServerRequest,
        timestamp: Instant,
        nonce: RequestNonce = RequestNonce.random(),
    ): RequestAuthentication {
        val millis = Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds())
        val signature = Ed25519.sign(keyPair.privateKey, canonicalInput(request, millis, nonce))
        return RequestAuthentication(millis, nonce, signature)
    }

    /**
     * `true` if [authentication] is a valid signature over [request] by the
     * holder of [publicKey]. Checks the signature only: time window and
     * nonce reuse are the server's job. Malformed keys, signatures and
     * requests give `false`.
     */
    fun verify(publicKey: ByteArray, request: ServerRequest, authentication: RequestAuthentication): Boolean {
        val input = try {
            canonicalInput(request, authentication.timestamp, authentication.nonce)
        } catch (e: IllegalArgumentException) {
            return false
        }
        return Ed25519.verify(publicKey, input, authentication.signature)
    }

    private val DOMAIN = ProtocolConstants.SERVER_AUTH_DOMAIN.encodeToByteArray()
}

/** Kodium's Ed25519 (TweetNaCl), kept behind this module's API. */
internal object Ed25519 {
    const val SEED_SIZE = 32
    const val PUBLIC_KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    fun generate(): DeviceAuthenticationKeyPair {
        val key = KodiumPrivateKey.generate()
        val seed = key.exportToArray()
        val publicKey = key.getPublicKey().signingKey.copyOf()
        key.secretKey.fill(0)
        return DeviceAuthenticationKeyPair(publicKey, seed)
    }

    fun sign(seed: ByteArray, data: ByteArray): ByteArray {
        require(seed.size == SEED_SIZE) { "Private key has an invalid size" }
        // fromRaw keeps a reference to its argument; pass a copy and wipe it.
        val copy = seed.copyOf()
        try {
            return Kodium.signDetached(KodiumPrivateKey.fromRaw(copy), data)
                .getOrElse { throw IllegalStateException("Signing failed", it) }
        } finally {
            copy.fill(0)
        }
    }

    /** The public key of [seed]. */
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == SEED_SIZE) { "Private key has an invalid size" }
        val copy = seed.copyOf()
        try {
            return KodiumPrivateKey.fromRaw(copy).getPublicKey().signingKey.copyOf()
        } finally {
            copy.fill(0)
        }
    }

    fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        publicKey.size == PUBLIC_KEY_SIZE &&
            signature.size == SIGNATURE_SIZE &&
            Kodium.verifyDetached(publicKey, data, signature)
}
