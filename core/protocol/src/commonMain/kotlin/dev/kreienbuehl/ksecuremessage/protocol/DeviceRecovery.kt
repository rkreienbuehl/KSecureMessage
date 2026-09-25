package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

// Device authentication recovery (docs/device-recovery.md): another
// registered device of the same user authorizes a replacement device
// authentication key for a device that lost its key. Server authentication
// only; the messaging identity is never touched.

/**
 * A device's request to replace its registered device authentication key
 * with [replacementPublicKey], to be authorized by [authorizer], another
 * device of the same user. [proofOfPossession] is the replacement key's
 * signature over the recovery statement ([DeviceRecovery]), so the request
 * cannot name a key its sender does not hold.
 *
 * Created by the target device with [DeviceRecovery.prepare]; transferred to
 * the authorizer by the application, for example with [DeviceRecoveryCodec].
 */
class DeviceRecoveryRequest(
    val target: DeviceAddress,
    val authorizer: DeviceAddress,
    replacementPublicKey: ByteArray,
    val timestamp: Instant,
    val nonce: RequestNonce,
    proofOfPossession: ByteArray,
) {
    private val key: ByteArray = replacementPublicKey.copyOf()
    private val pop: ByteArray = proofOfPossession.copyOf()

    init {
        require(key.size == DeviceRecovery.PUBLIC_KEY_SIZE) { "Replacement key has an invalid size" }
        require(pop.size == DeviceRecovery.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
        require(timestamp.toEpochMilliseconds() >= 0) { "Timestamp must not be before the epoch" }
        require(Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds()) == timestamp) {
            "Timestamp must be whole milliseconds"
        }
    }

    /** A copy of the replacement public key. */
    val replacementPublicKey: ByteArray get() = key.copyOf()

    /** A copy of the proof-of-possession signature. */
    val proofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "DeviceRecoveryRequest(target=$target, authorizer=$authorizer, timestamp=$timestamp)"
}

/**
 * A [request] authorized by its [DeviceRecoveryRequest.authorizer]:
 * [authorizerSignature] is the authorizer's device authentication key's
 * signature over the recovery statement. Carries both proofs; the target
 * device submits it to the server.
 */
class DeviceRecoveryAuthorization(
    val request: DeviceRecoveryRequest,
    authorizerSignature: ByteArray,
) {
    private val signature: ByteArray = authorizerSignature.copyOf()

    init {
        require(signature.size == DeviceRecovery.SIGNATURE_SIZE) { "Authorizer signature has an invalid size" }
    }

    /** A copy of the authorizer's signature. */
    val authorizerSignature: ByteArray get() = signature.copyOf()

    override fun toString(): String = "DeviceRecoveryAuthorization($request)"
}

/**
 * Identifies one recovery statement: 32 bytes, SHA-256 over the domain
 * `KSecureMessage-DeviceRecoveryId-v1` and the statement. The server records
 * the ID of the recovery that installed a device's current key, so a retry of
 * the same recovery is recognized. It is never an authorization.
 */
class DeviceRecoveryId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Device recovery ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is DeviceRecoveryId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "DeviceRecoveryId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * Device recovery format version 1 (docs/device-recovery.md). All three
 * constructions share the recovery statement:
 *
 * ```
 * u32 length | target userId (UTF-8)     | u32 length | target deviceId (UTF-8)
 * u32 length | authorizer userId (UTF-8) | u32 length | authorizer deviceId (UTF-8)
 * replacement public key (32)
 * timestamp: i64, epoch milliseconds
 * nonce (16)
 * ```
 *
 * and prefix it with `u32 length | domain (UTF-8)`:
 *
 * - authorization, Ed25519 by the authorizer's registered key:
 *   `KSecureMessage-DeviceRecovery-v1`;
 * - proof of possession, Ed25519 by the replacement key:
 *   `KSecureMessage-DeviceRecovery-PoP-v1`;
 * - [DeviceRecoveryId], SHA-256: `KSecureMessage-DeviceRecoveryId-v1`.
 *
 * Integers are big-endian. The domains keep the three apart from each other
 * and from server request signatures (`KSecureMessage-ServerAuth-v1`).
 */
object DeviceRecovery {
    /** Size of a device authentication public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a recovery signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /**
     * Accepted clock difference in each direction, by the authorizer and the
     * server: `now - VALIDITY_WINDOW <= timestamp <= now + VALIDITY_WINDOW`.
     * The same as for server requests.
     */
    val VALIDITY_WINDOW = 5.minutes

    /**
     * The target's request: [replacement] is the new key pair, [target] the
     * device whose registration it replaces, [authorizer] the device that is
     * asked to authorize it. [timestamp] is truncated to milliseconds.
     */
    fun prepare(
        replacement: DeviceAuthenticationKeyPair,
        target: DeviceAddress,
        authorizer: DeviceAddress,
        timestamp: Instant,
        nonce: RequestNonce = RequestNonce.random(),
    ): DeviceRecoveryRequest {
        val millis = Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds())
        val input = proofOfPossessionInput(target, authorizer, replacement.publicKey, millis, nonce)
        return DeviceRecoveryRequest(target, authorizer, replacement.publicKey, millis, nonce, Ed25519.sign(replacement.privateKey, input))
    }

    /**
     * Signs [request] with the authorizer's device authentication key pair.
     * Checks nothing: the caller verifies the request first.
     */
    fun authorize(authorizerKeyPair: DeviceAuthenticationKeyPair, request: DeviceRecoveryRequest): DeviceRecoveryAuthorization =
        DeviceRecoveryAuthorization(request, Ed25519.sign(authorizerKeyPair.privateKey, authorizationInput(request)))

    /** `true` if the request's proof of possession verifies with its replacement key. */
    fun verifyProofOfPossession(request: DeviceRecoveryRequest): Boolean =
        Ed25519.verify(request.replacementPublicKey, proofOfPossessionInput(request), request.proofOfPossession)

    /**
     * `true` if [authorization]'s authorizer signature verifies with
     * [authorizerPublicKey]. Does not check the proof of possession.
     */
    fun verifyAuthorization(authorizerPublicKey: ByteArray, authorization: DeviceRecoveryAuthorization): Boolean =
        Ed25519.verify(authorizerPublicKey, authorizationInput(authorization.request), authorization.authorizerSignature)

    /** The ID of [request]'s statement. */
    fun recoveryId(request: DeviceRecoveryRequest): DeviceRecoveryId =
        DeviceRecoveryId(SHA256().digest(domainInput(ID_DOMAIN, statement(request))))

    /** The bytes the authorizer signs. */
    fun authorizationInput(request: DeviceRecoveryRequest): ByteArray = domainInput(AUTHORIZATION_DOMAIN, statement(request))

    /** The bytes the replacement key signs. */
    fun proofOfPossessionInput(request: DeviceRecoveryRequest): ByteArray = domainInput(POP_DOMAIN, statement(request))

    private fun proofOfPossessionInput(
        target: DeviceAddress,
        authorizer: DeviceAddress,
        replacementPublicKey: ByteArray,
        timestamp: Instant,
        nonce: RequestNonce,
    ): ByteArray = domainInput(POP_DOMAIN, statement(target, authorizer, replacementPublicKey, timestamp, nonce))

    internal fun statement(request: DeviceRecoveryRequest): ByteArray =
        statement(request.target, request.authorizer, request.replacementPublicKey, request.timestamp, request.nonce)

    private fun statement(
        target: DeviceAddress,
        authorizer: DeviceAddress,
        replacementPublicKey: ByteArray,
        timestamp: Instant,
        nonce: RequestNonce,
    ): ByteArray {
        require(replacementPublicKey.size == PUBLIC_KEY_SIZE) { "Replacement key has an invalid size" }
        val out = BinaryWriter()
        out.address(target)
        out.address(authorizer)
        out.fixed(replacementPublicKey)
        out.long(timestamp.toEpochMilliseconds())
        out.fixed(nonce.bytes)
        return out.toByteArray()
    }

    private fun domainInput(domain: ByteArray, statement: ByteArray): ByteArray {
        val out = BinaryWriter()
        out.bytes(domain)
        out.fixed(statement)
        return out.toByteArray()
    }

    internal fun BinaryWriter.address(address: DeviceAddress) {
        bytes(address.userId.value.encodeToByteArray())
        bytes(address.deviceId.value.encodeToByteArray())
    }

    private val AUTHORIZATION_DOMAIN = ProtocolConstants.DEVICE_RECOVERY_DOMAIN.encodeToByteArray()
    private val POP_DOMAIN = ProtocolConstants.DEVICE_RECOVERY_POP_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.DEVICE_RECOVERY_ID_DOMAIN.encodeToByteArray()
}

/**
 * Transfer encoding of recovery requests and authorizations, version 1, for
 * applications that move them between devices (QR code, file, their own
 * channel). Not signed as such: the signatures inside cover the statement.
 *
 * ```
 * version:u8 = 1 | kind:u8 (1 request, 2 authorization) | statement
 * | proof of possession (64) | [authorizer signature (64), kind 2 only]
 * ```
 *
 * The statement is the one of [DeviceRecovery]. Decoding is strict (valid
 * UTF-8, exact sizes, no trailing bytes) and throws [IllegalArgumentException]
 * otherwise. Decoding verifies no signature.
 */
object DeviceRecoveryCodec {
    private const val VERSION: Byte = 1
    private const val KIND_REQUEST: Byte = 1
    private const val KIND_AUTHORIZATION: Byte = 2

    fun encodeRequest(request: DeviceRecoveryRequest): ByteArray = encode(KIND_REQUEST, request, null)

    fun encodeAuthorization(authorization: DeviceRecoveryAuthorization): ByteArray =
        encode(KIND_AUTHORIZATION, authorization.request, authorization.authorizerSignature)

    fun decodeRequest(bytes: ByteArray): DeviceRecoveryRequest {
        val reader = header(bytes, KIND_REQUEST)
        return reader.request().also { reader.requireEnd() }
    }

    fun decodeAuthorization(bytes: ByteArray): DeviceRecoveryAuthorization {
        val reader = header(bytes, KIND_AUTHORIZATION)
        val request = reader.request()
        return DeviceRecoveryAuthorization(request, reader.fixed(DeviceRecovery.SIGNATURE_SIZE)).also { reader.requireEnd() }
    }

    private fun encode(kind: Byte, request: DeviceRecoveryRequest, authorizerSignature: ByteArray?): ByteArray {
        val out = BinaryWriter()
        out.byte(VERSION)
        out.byte(kind)
        out.fixed(DeviceRecovery.statement(request))
        out.fixed(request.proofOfPossession)
        if (authorizerSignature != null) out.fixed(authorizerSignature)
        return out.toByteArray()
    }

    private fun header(bytes: ByteArray, kind: Byte): BinaryReader {
        val reader = BinaryReader(bytes)
        require(reader.byte() == VERSION) { "Unsupported device recovery format" }
        require(reader.byte() == kind) { "Unexpected device recovery record kind" }
        return reader
    }

    private fun BinaryReader.request(): DeviceRecoveryRequest {
        val target = address()
        val authorizer = address()
        val key = fixed(DeviceRecovery.PUBLIC_KEY_SIZE)
        val timestamp = long()
        require(timestamp >= 0) { "Timestamp must not be before the epoch" }
        val nonce = RequestNonce(fixed(RequestNonce.SIZE))
        val pop = fixed(DeviceRecovery.SIGNATURE_SIZE)
        return DeviceRecoveryRequest(target, authorizer, key, Instant.fromEpochMilliseconds(timestamp), nonce, pop)
    }

    private fun BinaryReader.address(): DeviceAddress = DeviceAddress(UserId(utf8()), DeviceId(utf8()))

    private fun BinaryReader.utf8(): String {
        val bytes = bytes()
        val value = bytes.decodeToString()
        // decodeToString replaces malformed sequences; a lossless round trip means valid UTF-8.
        require(value.encodeToByteArray().contentEquals(bytes)) { "Invalid UTF-8" }
        return value
    }

    private fun BinaryReader.long(): Long = (int().toLong() shl 32) or (int().toLong() and 0xFFFFFFFFL)
}
