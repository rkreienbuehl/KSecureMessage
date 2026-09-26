package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.UserId
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

// Offline recovery key lifecycle (docs/recovery-key-lifecycle.md): the
// last-device recovery key of a user (docs/last-device-recovery.md) is
// rotated or revoked only with two authorities at once: a ServerAuth v1
// request by a registered device of the user, and a signature by the current
// offline recovery key over a statement that names that device. A rotation's
// new key also proves possession. Neither a device alone nor the recovery
// key alone can change the recovery authority.

/**
 * The rotation a user asks for: [userId]'s recovery key [currentPublicKey],
 * registered at recovery key epoch [expectedEpoch], is to be replaced by
 * [newPublicKey], authorized by the device [authorizer] of the same user.
 * [timestamp] (whole milliseconds) and [nonce] make each statement single-use.
 */
class RecoveryKeyRotationStatement(
    val userId: UserId,
    val authorizer: DeviceAddress,
    currentPublicKey: ByteArray,
    newPublicKey: ByteArray,
    val expectedEpoch: Long,
    val timestamp: Instant,
    val nonce: RequestNonce,
) {
    private val current: ByteArray = currentPublicKey.copyOf()
    private val new: ByteArray = newPublicKey.copyOf()

    init {
        require(authorizer.userId == userId) { "The authorizing device must belong to the user" }
        require(current.size == RecoveryKeyRotation.PUBLIC_KEY_SIZE) { "Current recovery key has an invalid size" }
        require(new.size == RecoveryKeyRotation.PUBLIC_KEY_SIZE) { "New recovery key has an invalid size" }
        require(!current.contentEquals(new)) { "A rotation must change the recovery key" }
        requireEpochAndTimestamp(expectedEpoch, timestamp)
    }

    /** A copy of the current recovery public key. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    /** A copy of the new recovery public key. */
    val newPublicKey: ByteArray get() = new.copyOf()

    override fun toString(): String =
        "RecoveryKeyRotationStatement(userId=$userId, authorizer=$authorizer, expectedEpoch=$expectedEpoch, timestamp=$timestamp)"
}

/**
 * A [statement] with both proofs: [currentKeySignature] by the current
 * recovery key, [newKeyProofOfPossession] by the new recovery key.
 */
class RecoveryKeyRotationAuthorization(
    val statement: RecoveryKeyRotationStatement,
    currentKeySignature: ByteArray,
    newKeyProofOfPossession: ByteArray,
) {
    private val signature: ByteArray = currentKeySignature.copyOf()
    private val pop: ByteArray = newKeyProofOfPossession.copyOf()

    init {
        require(signature.size == RecoveryKeyRotation.SIGNATURE_SIZE) { "Recovery key signature has an invalid size" }
        require(pop.size == RecoveryKeyRotation.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
    }

    /** A copy of the current recovery key's signature. */
    val currentKeySignature: ByteArray get() = signature.copyOf()

    /** A copy of the new recovery key's signature. */
    val newKeyProofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "RecoveryKeyRotationAuthorization($statement)"
}

/**
 * Identifies one recovery key rotation statement: 32 bytes, SHA-256 over the
 * domain `KSecureMessage-RecoveryKeyRotationId-v1` and the statement. The
 * server records the ID of the rotation that installed the current recovery
 * key, so a retry of the same rotation is recognized. Never an authorization.
 */
class RecoveryKeyRotationId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Recovery key rotation ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is RecoveryKeyRotationId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RecoveryKeyRotationId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * The revocation a user asks for: [userId]'s recovery key [currentPublicKey],
 * registered at recovery key epoch [expectedEpoch], is to be removed without
 * a replacement, authorized by the device [authorizer] of the same user.
 */
class RecoveryKeyRevocationStatement(
    val userId: UserId,
    val authorizer: DeviceAddress,
    currentPublicKey: ByteArray,
    val expectedEpoch: Long,
    val timestamp: Instant,
    val nonce: RequestNonce,
) {
    private val current: ByteArray = currentPublicKey.copyOf()

    init {
        require(authorizer.userId == userId) { "The authorizing device must belong to the user" }
        require(current.size == RecoveryKeyRevocation.PUBLIC_KEY_SIZE) { "Current recovery key has an invalid size" }
        requireEpochAndTimestamp(expectedEpoch, timestamp)
    }

    /** A copy of the current recovery public key. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    override fun toString(): String =
        "RecoveryKeyRevocationStatement(userId=$userId, authorizer=$authorizer, expectedEpoch=$expectedEpoch, timestamp=$timestamp)"
}

/** A [statement] with the current recovery key's [signature]. */
class RecoveryKeyRevocationAuthorization(
    val statement: RecoveryKeyRevocationStatement,
    signature: ByteArray,
) {
    private val value: ByteArray = signature.copyOf()

    init {
        require(value.size == RecoveryKeyRevocation.SIGNATURE_SIZE) { "Recovery key signature has an invalid size" }
    }

    /** A copy of the current recovery key's signature. */
    val signature: ByteArray get() = value.copyOf()

    override fun toString(): String = "RecoveryKeyRevocationAuthorization($statement)"
}

/**
 * Identifies one recovery key revocation statement: 32 bytes, SHA-256 over
 * the domain `KSecureMessage-RecoveryKeyRevocationId-v1` and the statement.
 * Never an authorization.
 */
class RecoveryKeyRevocationId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Recovery key revocation ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is RecoveryKeyRevocationId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RecoveryKeyRevocationId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * Recovery key rotation, format version 1 (docs/recovery-key-lifecycle.md).
 * Rotation statement:
 *
 * ```
 * u32 length | userId (UTF-8)
 * u32 length | authorizer userId (UTF-8) | u32 length | authorizer deviceId (UTF-8)
 * current recovery public key (32)
 * new recovery public key (32)
 * expected recovery key epoch: i64 (>= 1)
 * timestamp: i64, epoch milliseconds
 * nonce (16)
 * ```
 *
 * Each construction prefixes `u32 length | domain (UTF-8)`:
 *
 * - authorization, Ed25519 by the current recovery key:
 *   `KSecureMessage-RecoveryKeyRotation-v1`;
 * - proof of possession, Ed25519 by the new recovery key:
 *   `KSecureMessage-RecoveryKeyRotation-NewKeyPoP-v1`;
 * - [RecoveryKeyRotationId], SHA-256: `KSecureMessage-RecoveryKeyRotationId-v1`.
 *
 * Integers are big-endian. No domain is shared with server request
 * authentication, device recovery, routine rotation or last-device recovery.
 */
object RecoveryKeyRotation {
    /** Size of a recovery public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /**
     * Accepted clock difference in each direction:
     * `now - VALIDITY_WINDOW <= timestamp <= now + VALIDITY_WINDOW`. The same
     * as for server requests.
     */
    val VALIDITY_WINDOW = 5.minutes

    /**
     * The rotation of [authorizer]'s user from [currentKey] (registered at
     * [expectedEpoch]) to [newKey], signed by both. [timestamp] is truncated
     * to milliseconds. Throws [IllegalArgumentException] if both keys are
     * the same.
     */
    fun authorize(
        currentKey: LastDeviceRecoveryKey,
        newKey: LastDeviceRecoveryKey,
        authorizer: DeviceAddress,
        expectedEpoch: Long,
        timestamp: Instant,
        nonce: RequestNonce = RequestNonce.random(),
    ): RecoveryKeyRotationAuthorization {
        val statement = RecoveryKeyRotationStatement(
            authorizer.userId, authorizer, currentKey.publicKey, newKey.publicKey, expectedEpoch, truncate(timestamp), nonce,
        )
        return RecoveryKeyRotationAuthorization(
            statement,
            currentKey.sign(authorizationInput(statement)),
            newKey.sign(proofOfPossessionInput(statement)),
        )
    }

    /**
     * `true` if [authorization]'s current key signature verifies with
     * [currentPublicKey]. The server passes the **registered** recovery key
     * (or, for an exact retry, the statement's). Does not check the proof of
     * possession.
     */
    fun verifyCurrentKeySignature(currentPublicKey: ByteArray, authorization: RecoveryKeyRotationAuthorization): Boolean =
        Ed25519.verify(currentPublicKey, authorizationInput(authorization.statement), authorization.currentKeySignature)

    /** `true` if the proof of possession verifies with the statement's new key. */
    fun verifyNewKeyProofOfPossession(authorization: RecoveryKeyRotationAuthorization): Boolean =
        Ed25519.verify(
            authorization.statement.newPublicKey,
            proofOfPossessionInput(authorization.statement),
            authorization.newKeyProofOfPossession,
        )

    /** The ID of [statement]. */
    fun rotationId(statement: RecoveryKeyRotationStatement): RecoveryKeyRotationId =
        RecoveryKeyRotationId(SHA256().digest(domainInput(ID_DOMAIN, statement(statement))))

    /** The bytes the current recovery key signs. */
    fun authorizationInput(statement: RecoveryKeyRotationStatement): ByteArray =
        domainInput(AUTHORIZATION_DOMAIN, statement(statement))

    /** The bytes the new recovery key signs. */
    fun proofOfPossessionInput(statement: RecoveryKeyRotationStatement): ByteArray =
        domainInput(POP_DOMAIN, statement(statement))

    internal fun statement(statement: RecoveryKeyRotationStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.userId.value.encodeToByteArray())
        out.bytes(statement.authorizer.userId.value.encodeToByteArray())
        out.bytes(statement.authorizer.deviceId.value.encodeToByteArray())
        out.fixed(statement.currentPublicKey)
        out.fixed(statement.newPublicKey)
        out.long(statement.expectedEpoch)
        out.long(statement.timestamp.toEpochMilliseconds())
        out.fixed(statement.nonce.bytes)
        return out.toByteArray()
    }

    private val AUTHORIZATION_DOMAIN = ProtocolConstants.RECOVERY_KEY_ROTATION_DOMAIN.encodeToByteArray()
    private val POP_DOMAIN = ProtocolConstants.RECOVERY_KEY_ROTATION_NEW_KEY_POP_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.RECOVERY_KEY_ROTATION_ID_DOMAIN.encodeToByteArray()
}

/**
 * Recovery key revocation, format version 1 (docs/recovery-key-lifecycle.md).
 * Revocation statement:
 *
 * ```
 * u32 length | userId (UTF-8)
 * u32 length | authorizer userId (UTF-8) | u32 length | authorizer deviceId (UTF-8)
 * current recovery public key (32)
 * expected recovery key epoch: i64 (>= 1)
 * timestamp: i64, epoch milliseconds
 * nonce (16)
 * ```
 *
 * Each construction prefixes `u32 length | domain (UTF-8)`:
 *
 * - authorization, Ed25519 by the current recovery key:
 *   `KSecureMessage-RecoveryKeyRevocation-v1`;
 * - [RecoveryKeyRevocationId], SHA-256: `KSecureMessage-RecoveryKeyRevocationId-v1`.
 */
object RecoveryKeyRevocation {
    /** Size of a recovery public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /** The revocation of [currentKey] (registered at [expectedEpoch]) for [authorizer]'s user, signed by it. */
    fun authorize(
        currentKey: LastDeviceRecoveryKey,
        authorizer: DeviceAddress,
        expectedEpoch: Long,
        timestamp: Instant,
        nonce: RequestNonce = RequestNonce.random(),
    ): RecoveryKeyRevocationAuthorization {
        val statement = RecoveryKeyRevocationStatement(
            authorizer.userId, authorizer, currentKey.publicKey, expectedEpoch, truncate(timestamp), nonce,
        )
        return RecoveryKeyRevocationAuthorization(statement, currentKey.sign(authorizationInput(statement)))
    }

    /**
     * `true` if [authorization]'s signature verifies with [currentPublicKey].
     * The server passes the **registered** recovery key (or, for an exact
     * retry, the statement's).
     */
    fun verifySignature(currentPublicKey: ByteArray, authorization: RecoveryKeyRevocationAuthorization): Boolean =
        Ed25519.verify(currentPublicKey, authorizationInput(authorization.statement), authorization.signature)

    /** The ID of [statement]. */
    fun revocationId(statement: RecoveryKeyRevocationStatement): RecoveryKeyRevocationId =
        RecoveryKeyRevocationId(SHA256().digest(domainInput(ID_DOMAIN, statement(statement))))

    /** The bytes the current recovery key signs. */
    fun authorizationInput(statement: RecoveryKeyRevocationStatement): ByteArray =
        domainInput(AUTHORIZATION_DOMAIN, statement(statement))

    internal fun statement(statement: RecoveryKeyRevocationStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.userId.value.encodeToByteArray())
        out.bytes(statement.authorizer.userId.value.encodeToByteArray())
        out.bytes(statement.authorizer.deviceId.value.encodeToByteArray())
        out.fixed(statement.currentPublicKey)
        out.long(statement.expectedEpoch)
        out.long(statement.timestamp.toEpochMilliseconds())
        out.fixed(statement.nonce.bytes)
        return out.toByteArray()
    }

    private val AUTHORIZATION_DOMAIN = ProtocolConstants.RECOVERY_KEY_REVOCATION_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.RECOVERY_KEY_REVOCATION_ID_DOMAIN.encodeToByteArray()
}

private fun requireEpochAndTimestamp(epoch: Long, timestamp: Instant) {
    require(epoch >= 1) { "Recovery key epoch must be positive" }
    require(timestamp.toEpochMilliseconds() >= 0) { "Timestamp must not be before the epoch" }
    require(Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds()) == timestamp) {
        "Timestamp must be whole milliseconds"
    }
}

private fun truncate(timestamp: Instant): Instant = Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds())

private fun domainInput(domain: ByteArray, statement: ByteArray): ByteArray {
    val out = BinaryWriter()
    out.bytes(domain)
    out.fixed(statement)
    return out.toByteArray()
}
