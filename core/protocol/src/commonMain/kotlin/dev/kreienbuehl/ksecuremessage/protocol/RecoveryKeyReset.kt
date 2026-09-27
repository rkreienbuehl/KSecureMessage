package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetId
import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import dev.kreienbuehl.ksecuremessage.model.UserId
import org.kotlincrypto.hash.sha2.SHA256
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

// Delayed recovery key reset (docs/recovery-key-reset.md): the exceptional
// replacement of a user's offline recovery key R1 when R1 is lost. A
// registered device requests it; the server enforces a policy delay during
// which every device of the user can see and cancel it, and so can R1 itself.
// After the delay a registered device completes it with the new key R2,
// which proves possession over a statement bound to the exact reset and the
// state it replaces. Weaker than a rotation (docs/recovery-key-lifecycle.md),
// which stays the normal path.

/**
 * The completion of the pending reset [resetId] of [userId]'s recovery key
 * [currentPublicKey] at recovery key epoch [expectedEpoch], requested at
 * [requestedAt] and eligible from [eligibleAt] (both server times, whole
 * milliseconds), with [newPublicKey], by the registered device [completer]
 * of the same user.
 */
class RecoveryKeyResetCompletionStatement(
    val userId: UserId,
    val resetId: RecoveryKeyResetId,
    val expectedEpoch: Long,
    currentPublicKey: ByteArray,
    newPublicKey: ByteArray,
    val requestedAt: Instant,
    val eligibleAt: Instant,
    val completer: DeviceAddress,
) {
    private val current: ByteArray = currentPublicKey.copyOf()
    private val new: ByteArray = newPublicKey.copyOf()

    init {
        require(completer.userId == userId) { "The completing device must belong to the user" }
        require(current.size == RecoveryKeyReset.PUBLIC_KEY_SIZE) { "Current recovery key has an invalid size" }
        require(new.size == RecoveryKeyReset.PUBLIC_KEY_SIZE) { "New recovery key has an invalid size" }
        require(!current.contentEquals(new)) { "A reset must change the recovery key" }
        requireResetBinding(expectedEpoch, requestedAt, eligibleAt)
    }

    /** A copy of the recovery public key being replaced. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    /** A copy of the new recovery public key. */
    val newPublicKey: ByteArray get() = new.copyOf()

    override fun toString(): String =
        "RecoveryKeyResetCompletionStatement(userId=$userId, completer=$completer, expectedEpoch=$expectedEpoch, eligibleAt=$eligibleAt)"
}

/** A completion [statement] with the new recovery key's [newKeyProofOfPossession]. */
class RecoveryKeyResetCompletionAuthorization(
    val statement: RecoveryKeyResetCompletionStatement,
    newKeyProofOfPossession: ByteArray,
) {
    private val pop: ByteArray = newKeyProofOfPossession.copyOf()

    init {
        require(pop.size == RecoveryKeyReset.SIGNATURE_SIZE) { "Proof of possession has an invalid size" }
    }

    /** A copy of the new recovery key's signature. */
    val newKeyProofOfPossession: ByteArray get() = pop.copyOf()

    override fun toString(): String = "RecoveryKeyResetCompletionAuthorization($statement)"
}

/**
 * Identifies one reset completion statement: 32 bytes, SHA-256 over the
 * domain `KSecureMessage-RecoveryKeyResetId-v1` and the statement. The server
 * records the ID of the completion that installed the current recovery key,
 * so a retry of the same completion is recognized. Never an authorization.
 * Not the server-chosen [RecoveryKeyResetId] of the pending reset.
 */
class RecoveryKeyResetCompletionId(bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Recovery key reset completion ID must have $SIZE bytes" }
    }

    /** A copy of the 32 ID bytes. */
    val bytes: ByteArray get() = value.copyOf()

    override fun equals(other: Any?): Boolean = other is RecoveryKeyResetCompletionId && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RecoveryKeyResetCompletionId(<redacted>)"

    companion object {
        const val SIZE: Int = 32
    }
}

/**
 * The cancellation of the pending reset [resetId] of [userId]'s recovery key
 * [currentPublicKey] at [expectedEpoch] (requested at [requestedAt], eligible
 * from [eligibleAt]) by that recovery key itself.
 */
class RecoveryKeyResetCancellationStatement(
    val userId: UserId,
    val resetId: RecoveryKeyResetId,
    val expectedEpoch: Long,
    currentPublicKey: ByteArray,
    val requestedAt: Instant,
    val eligibleAt: Instant,
) {
    private val current: ByteArray = currentPublicKey.copyOf()

    init {
        require(current.size == RecoveryKeyReset.PUBLIC_KEY_SIZE) { "Current recovery key has an invalid size" }
        requireResetBinding(expectedEpoch, requestedAt, eligibleAt)
    }

    /** A copy of the current recovery public key. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    override fun toString(): String =
        "RecoveryKeyResetCancellationStatement(userId=$userId, expectedEpoch=$expectedEpoch, eligibleAt=$eligibleAt)"
}

/** A cancellation [statement] with the current recovery key's [signature]. */
class RecoveryKeyResetCancellationAuthorization(
    val statement: RecoveryKeyResetCancellationStatement,
    signature: ByteArray,
) {
    private val value: ByteArray = signature.copyOf()

    init {
        require(value.size == RecoveryKeyReset.SIGNATURE_SIZE) { "Recovery key signature has an invalid size" }
    }

    /** A copy of the current recovery key's signature. */
    val signature: ByteArray get() = value.copyOf()

    override fun toString(): String = "RecoveryKeyResetCancellationAuthorization($statement)"
}

/**
 * A query for [userId]'s pending reset by the holder of its current recovery
 * key [currentPublicKey] at [timestamp] (whole milliseconds, checked against
 * the server clock with [RecoveryKeyReset.VALIDITY_WINDOW]).
 */
class RecoveryKeyResetStatusQueryStatement(
    val userId: UserId,
    currentPublicKey: ByteArray,
    val timestamp: Instant,
) {
    private val current: ByteArray = currentPublicKey.copyOf()

    init {
        require(current.size == RecoveryKeyReset.PUBLIC_KEY_SIZE) { "Current recovery key has an invalid size" }
        requireWholeMilliseconds(timestamp, "Timestamp")
    }

    /** A copy of the current recovery public key. */
    val currentPublicKey: ByteArray get() = current.copyOf()

    override fun toString(): String = "RecoveryKeyResetStatusQueryStatement(userId=$userId, timestamp=$timestamp)"
}

/** A status query [statement] with the current recovery key's [signature]. */
class RecoveryKeyResetStatusQuery(
    val statement: RecoveryKeyResetStatusQueryStatement,
    signature: ByteArray,
) {
    private val value: ByteArray = signature.copyOf()

    init {
        require(value.size == RecoveryKeyReset.SIGNATURE_SIZE) { "Recovery key signature has an invalid size" }
    }

    /** A copy of the current recovery key's signature. */
    val signature: ByteArray get() = value.copyOf()

    override fun toString(): String = "RecoveryKeyResetStatusQuery($statement)"
}

/**
 * Delayed recovery key reset, format version 1 (docs/recovery-key-reset.md).
 * Integers are big-endian, strings `u32 length | UTF-8`.
 *
 * Completion statement:
 *
 * ```
 * u32 length | userId
 * reset ID (16)
 * expected recovery key epoch: i64 (>= 1)
 * current recovery public key (32)
 * new recovery public key (32)            // ≠ current
 * requestedAt: i64, epoch milliseconds (>= 0)
 * eligibleAt: i64, epoch milliseconds (> requestedAt)
 * u32 length | completer userId           // = userId
 * u32 length | completer deviceId
 * ```
 *
 * Cancellation statement:
 *
 * ```
 * u32 length | userId
 * reset ID (16)
 * expected recovery key epoch: i64
 * current recovery public key (32)
 * requestedAt: i64 | eligibleAt: i64
 * ```
 *
 * Status query statement:
 *
 * ```
 * u32 length | userId
 * current recovery public key (32)
 * timestamp: i64, epoch milliseconds
 * ```
 *
 * Each construction prefixes `u32 length | domain (UTF-8)`:
 *
 * - completion proof of possession, Ed25519 by the new recovery key:
 *   `KSecureMessage-RecoveryKeyReset-NewKeyPoP-v1`;
 * - [RecoveryKeyResetCompletionId], SHA-256: `KSecureMessage-RecoveryKeyResetId-v1`;
 * - cancellation, Ed25519 by the current recovery key:
 *   `KSecureMessage-RecoveryKeyReset-Cancel-v1`;
 * - status query, Ed25519 by the current recovery key:
 *   `KSecureMessage-RecoveryKeyResetStatusQuery-v1`.
 *
 * No domain is shared with any other construction.
 */
object RecoveryKeyReset {
    /** Size of a recovery public key (Ed25519). */
    const val PUBLIC_KEY_SIZE: Int = Ed25519.PUBLIC_KEY_SIZE

    /** Size of a signature (Ed25519). */
    const val SIGNATURE_SIZE: Int = Ed25519.SIGNATURE_SIZE

    /**
     * Accepted clock difference of a status query in each direction:
     * `now - VALIDITY_WINDOW <= timestamp <= now + VALIDITY_WINDOW`.
     */
    val VALIDITY_WINDOW = 5.minutes

    /**
     * The completion of [reset] with [newKey] by [completer], signed by
     * [newKey]. The application must have backed up [newKey] before it sends
     * this. Throws [IllegalArgumentException] if [newKey] is the key being
     * replaced or [completer] belongs to another user.
     */
    fun complete(
        newKey: LastDeviceRecoveryKey,
        reset: RecoveryKeyResetStatus.Pending,
        completer: DeviceAddress,
    ): RecoveryKeyResetCompletionAuthorization {
        val statement = RecoveryKeyResetCompletionStatement(
            reset.userId, reset.resetId, reset.recoveryKeyEpoch, reset.recoveryPublicKey, newKey.publicKey,
            reset.requestedAt, reset.eligibleAt, completer,
        )
        return RecoveryKeyResetCompletionAuthorization(statement, newKey.sign(proofOfPossessionInput(statement)))
    }

    /**
     * The cancellation of [reset] by the recovery key it would replace,
     * [currentKey]. Throws [IllegalArgumentException] if [currentKey] is not
     * the key [reset] replaces.
     */
    fun cancel(currentKey: LastDeviceRecoveryKey, reset: RecoveryKeyResetStatus.Pending): RecoveryKeyResetCancellationAuthorization {
        require(currentKey.publicKey.contentEquals(reset.recoveryPublicKey)) { "Not the recovery key the reset replaces" }
        val statement = RecoveryKeyResetCancellationStatement(
            reset.userId, reset.resetId, reset.recoveryKeyEpoch, currentKey.publicKey, reset.requestedAt, reset.eligibleAt,
        )
        return RecoveryKeyResetCancellationAuthorization(statement, currentKey.sign(cancellationInput(statement)))
    }

    /** A status query for [userId]'s pending reset, signed by [currentKey]. [timestamp] is truncated to milliseconds. */
    fun statusQuery(currentKey: LastDeviceRecoveryKey, userId: UserId, timestamp: Instant): RecoveryKeyResetStatusQuery {
        val statement = RecoveryKeyResetStatusQueryStatement(userId, currentKey.publicKey, truncate(timestamp))
        return RecoveryKeyResetStatusQuery(statement, currentKey.sign(statusQueryInput(statement)))
    }

    /** `true` if the proof of possession verifies with the statement's new key. */
    fun verifyNewKeyProofOfPossession(authorization: RecoveryKeyResetCompletionAuthorization): Boolean =
        Ed25519.verify(
            authorization.statement.newPublicKey,
            proofOfPossessionInput(authorization.statement),
            authorization.newKeyProofOfPossession,
        )

    /** `true` if the cancellation verifies with [currentPublicKey]; the server passes the **registered** recovery key. */
    fun verifyCancellation(currentPublicKey: ByteArray, authorization: RecoveryKeyResetCancellationAuthorization): Boolean =
        Ed25519.verify(currentPublicKey, cancellationInput(authorization.statement), authorization.signature)

    /** `true` if the status query verifies with [currentPublicKey]; the server passes the **registered** recovery key. */
    fun verifyStatusQuery(currentPublicKey: ByteArray, query: RecoveryKeyResetStatusQuery): Boolean =
        Ed25519.verify(currentPublicKey, statusQueryInput(query.statement), query.signature)

    /** The ID of [statement]. */
    fun completionId(statement: RecoveryKeyResetCompletionStatement): RecoveryKeyResetCompletionId =
        RecoveryKeyResetCompletionId(SHA256().digest(domainInput(ID_DOMAIN, completionStatement(statement))))

    /** The bytes the new recovery key signs. */
    fun proofOfPossessionInput(statement: RecoveryKeyResetCompletionStatement): ByteArray =
        domainInput(POP_DOMAIN, completionStatement(statement))

    /** The bytes the current recovery key signs to cancel. */
    fun cancellationInput(statement: RecoveryKeyResetCancellationStatement): ByteArray =
        domainInput(CANCEL_DOMAIN, cancellationStatement(statement))

    /** The bytes the current recovery key signs to query the status. */
    fun statusQueryInput(statement: RecoveryKeyResetStatusQueryStatement): ByteArray =
        domainInput(STATUS_QUERY_DOMAIN, statusQueryStatement(statement))

    internal fun completionStatement(statement: RecoveryKeyResetCompletionStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.userId.value.encodeToByteArray())
        out.fixed(statement.resetId.bytes)
        out.long(statement.expectedEpoch)
        out.fixed(statement.currentPublicKey)
        out.fixed(statement.newPublicKey)
        out.long(statement.requestedAt.toEpochMilliseconds())
        out.long(statement.eligibleAt.toEpochMilliseconds())
        out.bytes(statement.completer.userId.value.encodeToByteArray())
        out.bytes(statement.completer.deviceId.value.encodeToByteArray())
        return out.toByteArray()
    }

    internal fun cancellationStatement(statement: RecoveryKeyResetCancellationStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.userId.value.encodeToByteArray())
        out.fixed(statement.resetId.bytes)
        out.long(statement.expectedEpoch)
        out.fixed(statement.currentPublicKey)
        out.long(statement.requestedAt.toEpochMilliseconds())
        out.long(statement.eligibleAt.toEpochMilliseconds())
        return out.toByteArray()
    }

    internal fun statusQueryStatement(statement: RecoveryKeyResetStatusQueryStatement): ByteArray {
        val out = BinaryWriter()
        out.bytes(statement.userId.value.encodeToByteArray())
        out.fixed(statement.currentPublicKey)
        out.long(statement.timestamp.toEpochMilliseconds())
        return out.toByteArray()
    }

    private val POP_DOMAIN = ProtocolConstants.RECOVERY_KEY_RESET_NEW_KEY_POP_DOMAIN.encodeToByteArray()
    private val ID_DOMAIN = ProtocolConstants.RECOVERY_KEY_RESET_ID_DOMAIN.encodeToByteArray()
    private val CANCEL_DOMAIN = ProtocolConstants.RECOVERY_KEY_RESET_CANCEL_DOMAIN.encodeToByteArray()
    private val STATUS_QUERY_DOMAIN = ProtocolConstants.RECOVERY_KEY_RESET_STATUS_QUERY_DOMAIN.encodeToByteArray()
}

private fun requireResetBinding(epoch: Long, requestedAt: Instant, eligibleAt: Instant) {
    require(epoch >= 1) { "Recovery key epoch must be positive" }
    requireWholeMilliseconds(requestedAt, "Request time")
    requireWholeMilliseconds(eligibleAt, "Eligibility time")
    require(eligibleAt > requestedAt) { "A reset becomes eligible after it was requested" }
}

private fun requireWholeMilliseconds(time: Instant, name: String) {
    require(time.toEpochMilliseconds() >= 0) { "$name must not be before the epoch" }
    require(Instant.fromEpochMilliseconds(time.toEpochMilliseconds()) == time) { "$name must be whole milliseconds" }
}

private fun truncate(timestamp: Instant): Instant = Instant.fromEpochMilliseconds(timestamp.toEpochMilliseconds())

private fun domainInput(domain: ByteArray, statement: ByteArray): ByteArray {
    val out = BinaryWriter()
    out.bytes(domain)
    out.fixed(statement)
    return out.toByteArray()
}
