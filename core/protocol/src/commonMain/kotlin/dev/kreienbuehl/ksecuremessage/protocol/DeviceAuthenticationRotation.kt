package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

// Routine device authentication key rotation (docs/device-authentication-rotation.md):
// a device that still holds its registered key K1 replaces it with K2. K1
// authorizes the transition, K2 proves possession. Server authentication only;
// the messaging identity is never touched. Not a device recovery
// (docs/device-recovery.md): other domains, other endpoint, no other device.

/**
 * The transition a routine rotation asks for: [address]'s registered key
 * [currentPublicKey] at authentication epoch [expectedAuthEpoch] is to be
 * replaced by [replacementPublicKey]. [timestamp] (whole milliseconds) and
 * [nonce] make each statement single-use.
 */
class DeviceAuthenticationRotationStatement(
    val address: DeviceAddress,
    currentPublicKey: ByteArray,
    replacementPublicKey: ByteArray,
    val expectedAuthEpoch: Long,
    val timestamp: Instant,
    val nonce: RequestNonce,
) {
    private val current: ByteArray = currentPublicKey.copyOf()
    private val replacement: ByteArray = replacementPublicKey.copyOf()

    init {
        require(current.size == DeviceAuthenticationRotation.PUBLIC_KEY_SIZE) { "Current key has an invalid size" }
        require(replacement.size == DeviceAuthenticationRotation.PUBLIC_KEY_SIZE) { "Replacement key has an invalid size" }
        require(!current.contentEquals(replacement)) { "A rotation must change the key" }
        require(expectedAuthEpoch >= 1) { "Authentication epoch must be positive" }
        require(timestamp.toEpochMilliseconds() >= 0) { "Timestamp must not be before the epoch" }
        require(Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds()) == timestamp) {
            "Timestamp must be whole milliseconds"
        }
    }

    /** A copy of the current (authorizing) public key. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    /** A copy of the replacement public key. */
    val replacementPublicKey: ByteArray get() = replacement.copyOf()

    override fun toString(): String =
        "DeviceAuthenticationRotationStatement(address=$address, expectedAuthEpoch=$expectedAuthEpoch, timestamp=$timestamp)"
}

/**
 * A [statement] with both proofs: [authorizationSignature] by the current
 * key, [proofOfPossession] by the replacement key.
 */
class DeviceAuthenticationRotationAuthorization(
    val statement: DeviceAuthenticationRotationStatement,
    authorizationSignature: ByteArray,
    proofOfPossession: ByteArray,
) {
    private val signature: ByteArray = authorizationSignature.copyOf()
    private val pop: ByteArray = proofOfPossession.copyOf()

    init {
        require(signature.size == DeviceAuthenticationRotation.SIGNATURE_SIZE) { "Authorization signature has an invalid size" }
        require(pop.size == DeviceAuthenticationRotation.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
    }

    /** A copy of the current key's signature. */
    val authorizationSignature: ByteArray get() = signature.copyOf()

    /** A copy of the replacement key's signature. */
    val proofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "DeviceAuthenticationRotationAuthorization($statement)"
}

/**
 * Identifies one rotation statement: 32 bytes, SHA-256 over the domain
 * `KSecureMessage-DeviceAuthRotationId-v1` and the statement. The server
 * records the ID of the rotation that installed a device's current key, so a
 * retry of the same rotation is recognized. It is never an authorization.
 */
class DeviceAuthenticationRotationId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Device authentication rotation ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is DeviceAuthenticationRotationId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "DeviceAuthenticationRotationId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * Routine device authentication key rotation, format version 1
 * (docs/device-authentication-rotation.md). All three constructions share
 * the rotation statement:
 *
 * ```
 * u32 length | userId (UTF-8) | u32 length | deviceId (UTF-8)
 * current public key (32)
 * replacement public key (32)
 * expected authentication epoch: i64 (>= 1)
 * timestamp: i64, epoch milliseconds
 * nonce (16)
 * ```
 *
 * and prefix it with `u32 length | domain (UTF-8)`:
 *
 * - authorization, Ed25519 by the current key:
 *   `KSecureMessage-DeviceAuthRotation-v1`;
 * - proof of possession, Ed25519 by the replacement key:
 *   `KSecureMessage-DeviceAuthRotation-PoP-v1`;
 * - [DeviceAuthenticationRotationId], SHA-256:
 *   `KSecureMessage-DeviceAuthRotationId-v1`.
 *
 * Integers are big-endian. The domains keep the three apart from each other,
 * from device recovery and from server request signatures.
 */
object DeviceAuthenticationRotation {
    /** Size of a device authentication public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a rotation signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /**
     * Accepted clock difference in each direction:
     * `now - VALIDITY_WINDOW <= timestamp <= now + VALIDITY_WINDOW`. The same
     * as for server requests and device recovery.
     */
    val VALIDITY_WINDOW = 5.minutes

    /**
     * The statement for replacing [current] (registered for [address] at
     * [expectedAuthEpoch]) with [replacement], signed by both keys.
     * [timestamp] is truncated to milliseconds. Throws
     * [IllegalArgumentException] if both keys are the same.
     */
    fun create(
        current: DeviceAuthenticationKeyPair,
        replacement: DeviceAuthenticationKeyPair,
        address: DeviceAddress,
        expectedAuthEpoch: Long,
        timestamp: Instant,
        nonce: RequestNonce = RequestNonce.random(),
    ): DeviceAuthenticationRotationAuthorization {
        val millis = Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds())
        val statement = DeviceAuthenticationRotationStatement(
            address, current.publicKey, replacement.publicKey, expectedAuthEpoch, millis, nonce,
        )
        return DeviceAuthenticationRotationAuthorization(
            statement,
            Ed25519.sign(current.privateKey, authorizationInput(statement)),
            Ed25519.sign(replacement.privateKey, proofOfPossessionInput(statement)),
        )
    }

    /**
     * `true` if [authorization]'s authorization signature verifies with
     * [currentPublicKey]. The server passes the **registered** key. Does not
     * check the proof of possession.
     */
    fun verifyAuthorization(currentPublicKey: ByteArray, authorization: DeviceAuthenticationRotationAuthorization): Boolean =
        Ed25519.verify(currentPublicKey, authorizationInput(authorization.statement), authorization.authorizationSignature)

    /** `true` if the proof of possession verifies with the statement's replacement key. */
    fun verifyProofOfPossession(authorization: DeviceAuthenticationRotationAuthorization): Boolean =
        Ed25519.verify(
            authorization.statement.replacementPublicKey,
            proofOfPossessionInput(authorization.statement),
            authorization.proofOfPossession,
        )

    /** The ID of [statement]. */
    fun rotationId(statement: DeviceAuthenticationRotationStatement): DeviceAuthenticationRotationId =
        DeviceAuthenticationRotationId(SHA256().digest(domainInput(ID_DOMAIN, statement(statement))))

    /** The bytes the current key signs. */
    fun authorizationInput(statement: DeviceAuthenticationRotationStatement): ByteArray =
        domainInput(AUTHORIZATION_DOMAIN, statement(statement))

    /** The bytes the replacement key signs. */
    fun proofOfPossessionInput(statement: DeviceAuthenticationRotationStatement): ByteArray =
        domainInput(POP_DOMAIN, statement(statement))

    internal fun statement(statement: DeviceAuthenticationRotationStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.address.userId.value.encodeToByteArray())
        out.bytes(statement.address.deviceId.value.encodeToByteArray())
        out.fixed(statement.currentPublicKey)
        out.fixed(statement.replacementPublicKey)
        out.long(statement.expectedAuthEpoch)
        out.long(statement.timestamp.toEpochMilliseconds())
        out.fixed(statement.nonce.bytes)
        return out.toByteArray()
    }

    private fun domainInput(domain: ByteArray, statement: ByteArray): ByteArray {
        val out = BinaryWriter()
        out.bytes(domain)
        out.fixed(statement)
        return out.toByteArray()
    }

    private val AUTHORIZATION_DOMAIN = ProtocolConstants.DEVICE_AUTH_ROTATION_DOMAIN.encodeToByteArray()
    private val POP_DOMAIN = ProtocolConstants.DEVICE_AUTH_ROTATION_POP_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.DEVICE_AUTH_ROTATION_ID_DOMAIN.encodeToByteArray()
}
