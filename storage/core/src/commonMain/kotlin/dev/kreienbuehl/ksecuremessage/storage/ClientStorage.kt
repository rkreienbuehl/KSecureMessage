package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.VerificationState
import kotlin.time.Instant

// Every store below except RemoteIdentityStore, SessionInitiationStore and ProcessedInboundStore holds
// secret key material, ratchet state or application message content. The interfaces exchange them as
// plaintext; PendingOutboundStore holds the plaintext of sent messages until the recipient acknowledges them.
// A persistent adapter must encrypt them at rest (SqlDelightClientStorage seals them with storage:encryption,
// see docs/storage-encryption.md) and must fail, never return null, when a stored record cannot be read.
// InMemoryClientStorage persists nothing and does not encrypt. See docs/storage.md.

interface SessionStore {
    suspend fun load(address: DeviceAddress): SecureSession?
    suspend fun store(session: SecureSession)
    suspend fun remove(address: DeviceAddress)
}

/** The local device's long-term identity key pair. There is at most one. */
interface IdentityStore {
    suspend fun identity(): LocalIdentity?

    /**
     * Stores the local identity. Throws [IllegalStateException] if one exists
     * already: an identity is never replaced silently.
     */
    suspend fun store(identity: LocalIdentity)
}

/**
 * The local device's authentication key pair (docs/server-authentication.md),
 * separate from the messaging identity. There is at most one active key. It
 * is replaced only by promoting a pending key after the server accepted it:
 * the pending recovery key of a device recovery (docs/device-recovery.md),
 * the pending rotation key of a routine rotation
 * (docs/device-authentication-rotation.md) or the pending last-device
 * recovery key of a last-device recovery (docs/last-device-recovery.md). The
 * three pending slots are separate, and at most one of them is filled at a
 * time.
 */
interface DeviceAuthenticationKeyStore {
    suspend fun keyPair(): DeviceAuthenticationKeyPair?

    /**
     * Stores the key pair. Throws [IllegalStateException] if one exists
     * already, also an identical one: a key is never replaced silently.
     */
    suspend fun store(keyPair: DeviceAuthenticationKeyPair)

    /**
     * `true` only for storage that held a local identity before device
     * authentication keys existed (milestone 12) and has not stored a key
     * since. Such an installation gets its first key from
     * `SecureMessageClient.initialize`. For any other storage a missing key
     * means it was lost, and a new one must not be created. Storing a key
     * makes this `false` for good.
     */
    suspend fun awaitsUpgradeKey(): Boolean

    /**
     * The replacement key pair of a device recovery in progress
     * (docs/device-recovery.md), or `null`. Never used to sign ordinary
     * requests.
     */
    suspend fun pendingRecoveryKeyPair(): DeviceAuthenticationKeyPair?

    /**
     * Stores the replacement key pair of a device recovery. Throws
     * [IllegalStateException] if one exists already (a pending key is never
     * replaced silently) or if a routine rotation or a last-device recovery
     * is pending. The active key is not touched.
     */
    suspend fun storePendingRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair)

    /** Removes the pending recovery key pair, if any. The active key is not touched. */
    suspend fun removePendingRecoveryKeyPair()

    /**
     * In one atomic step: makes the pending recovery key pair the active key
     * (replacing the active key, or installing it if the active key was
     * lost), removes the pending key and makes [awaitsUpgradeKey] `false`.
     * Only for a pending key the server accepted. Throws
     * [IllegalStateException] and changes nothing if there is no pending key.
     */
    suspend fun promotePendingRecoveryKeyPair()

    /**
     * The replacement key pair of a routine rotation in progress
     * (docs/device-authentication-rotation.md), or `null`. Never used to
     * sign ordinary requests.
     */
    suspend fun pendingRotationKeyPair(): DeviceAuthenticationKeyPair?

    /**
     * Stores the replacement key pair of a routine rotation. Throws
     * [IllegalStateException] if one exists already (a pending key is never
     * replaced silently) or if a device recovery or a last-device recovery is
     * pending. The active key is not touched.
     */
    suspend fun storePendingRotationKeyPair(keyPair: DeviceAuthenticationKeyPair)

    /** Removes the pending rotation key pair, if any. The active key and a pending recovery key are not touched. */
    suspend fun removePendingRotationKeyPair()

    /**
     * In one atomic step: makes the pending rotation key pair the active key
     * (replacing the active key, or installing it if the active key was
     * lost), removes the pending key and makes [awaitsUpgradeKey] `false`.
     * Only for a pending key the server accepted. Throws
     * [IllegalStateException] and changes nothing if there is no pending key.
     */
    suspend fun promotePendingRotationKeyPair()

    /**
     * The replacement key pair of a last-device recovery in progress
     * (docs/last-device-recovery.md), or `null`. Never used to sign ordinary
     * requests.
     */
    suspend fun pendingLastDeviceRecoveryKeyPair(): DeviceAuthenticationKeyPair?

    /**
     * Stores the replacement key pair of a last-device recovery. Throws
     * [IllegalStateException] if one exists already (a pending key is never
     * replaced silently) or if a device recovery or a routine rotation is
     * pending. The active key is not touched.
     */
    suspend fun storePendingLastDeviceRecoveryKeyPair(keyPair: DeviceAuthenticationKeyPair)

    /** Removes the pending last-device recovery key pair, if any. The active key and the other slots are not touched. */
    suspend fun removePendingLastDeviceRecoveryKeyPair()

    /**
     * In one atomic step: makes the pending last-device recovery key pair
     * the active key (replacing the active key, or installing it if the
     * active key was lost), removes the pending key and makes
     * [awaitsUpgradeKey] `false`. Only for a pending key the server accepted.
     * Throws [IllegalStateException] and changes nothing if there is no
     * pending key.
     */
    suspend fun promotePendingLastDeviceRecoveryKeyPair()
}

/**
 * A pinned remote identity key and whether the user verified exactly this key
 * (docs/identity-verification.md). [identityKey] is a copy.
 */
class RemoteIdentityRecord(
    val identityKey: ByteArray,
    val verification: VerificationState,
)

/**
 * Remote identity keys pinned on first contact (trust on first use, see
 * docs/identity-trust.md). One public identity key per remote [DeviceAddress];
 * two devices of the same user have separate entries.
 *
 * Keys are public, but a pin is security state: it is never removed and never
 * replaced silently. The client pins a key only after the first contact with
 * it succeeded cryptographically, and replaces it only when the application
 * explicitly accepted an identity change ([replace]).
 *
 * Each pin carries a [VerificationState] that belongs to exactly the pinned
 * key: a new pin starts [VerificationState.UNVERIFIED], and so does a
 * replaced one. Verification is never carried over to another key.
 */
interface RemoteIdentityStore {
    suspend fun identityKey(address: DeviceAddress): ByteArray?

    /** The pin of [address] with its verification state, or `null`. */
    suspend fun record(address: DeviceAddress): RemoteIdentityRecord?

    /**
     * Pins [identityKey] for [address] as [VerificationState.UNVERIFIED].
     * Storing the key that is already pinned does nothing (its verification
     * state stays). Throws [IllegalStateException] if a different key is
     * pinned: a pin is never replaced silently.
     */
    suspend fun store(address: DeviceAddress, identityKey: ByteArray)

    /**
     * Sets the verification state of the pin of [address], but only if the
     * pinned key is [identityKey]. Throws [IllegalStateException] and changes
     * nothing if there is no pin or another key is pinned.
     */
    suspend fun setVerification(address: DeviceAddress, identityKey: ByteArray, verification: VerificationState)

    /**
     * Replaces the pin of [address] with [newIdentityKey] as
     * [VerificationState.UNVERIFIED], but only if [expectedIdentityKey] is
     * pinned (compare-and-set). Throws [IllegalStateException] and changes
     * nothing if there is no pin or another key is pinned, and
     * [IllegalArgumentException] if both keys are equal. Only for an identity
     * change the application explicitly accepted.
     */
    suspend fun replace(address: DeviceAddress, expectedIdentityKey: ByteArray, newIdentityKey: ByteArray)
}

/**
 * Session initiations from a remote device that must never become the current
 * session again (see docs/session-lifecycle.md): initiations whose session
 * was replaced, and initiations that lost a simultaneous-initiation collision.
 * Kept per remote [DeviceAddress]. IDs are public values.
 *
 * The client retires an ID in the same transaction that replaces the session
 * or rejects the initiation, so the entry survives restarts together with that
 * decision. Each entry may name the local signed prekey that accepting the
 * initiation needs. Entries are removed only through [removeRetiredFor], once
 * that signed prekey is deleted for good and the initiation can no longer be
 * accepted anyway (docs/signed-prekey-lifecycle.md). Entries without a signed
 * prekey ID are kept forever.
 */
interface SessionInitiationStore {
    suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId): Boolean

    /**
     * Retires [id] for [remote]. [signedPreKeyId] is the local signed prekey
     * the initiation was accepted with, or `null` if unknown or not a local
     * key. Retiring an ID twice does nothing: the first entry is kept.
     */
    suspend fun retire(remote: DeviceAddress, id: SessionInitiationId, signedPreKeyId: SignedPreKeyId?)

    /** The distinct signed prekey IDs that retired entries name, over all remote devices. */
    suspend fun retiredSignedPreKeyIds(): Set<SignedPreKeyId>

    /** Removes every retired entry, of any remote device, that names [signedPreKeyId]. */
    suspend fun removeRetiredFor(signedPreKeyId: SignedPreKeyId)
}

/**
 * Lifecycle metadata of one stored signed prekey. Holds no key material.
 *
 * @property isCurrent `true` for the signed prekey to publish.
 * @property createdAt when the key was stored; `null` for a key stored before
 *   milestone 7 that was not stamped yet (see [PreKeyStore.stampLegacySignedPreKeys]).
 * @property replacedAt when a newer key became current and this one entered
 *   its grace period; `null` for the current key and unstamped old keys.
 */
data class SignedPreKeyInfo(
    val id: SignedPreKeyId,
    val isCurrent: Boolean,
    val createdAt: Instant?,
    val replacedAt: Instant?,
)

/**
 * The local device's private prekeys.
 *
 * Signed prekeys follow a lifecycle (docs/signed-prekey-lifecycle.md): the
 * current one is published; [storeCurrentSignedPreKey] moves it into a grace
 * period in which an incoming `PreKeyMessage` may still name it; the client
 * deletes it with [removeSignedPreKey] once the grace period is over. Storage
 * only records the timestamps, the client makes the decisions.
 *
 * IDs are allocated upward from a persisted high-water mark (the highest ID
 * ever stored, see [highestSignedPreKeyId] and [highestOneTimePreKeyId]).
 * Removing a key does not lower it, so IDs are never reused. Storing a key
 * whose ID is not above the high-water mark throws [IllegalArgumentException].
 */
interface PreKeyStore {
    /** Any stored signed prekey, current or replaced. */
    suspend fun signedPreKey(id: SignedPreKeyId): SignedPreKeyPair?

    /** The signed prekey to publish, or `null` if none was stored yet. */
    suspend fun currentSignedPreKey(): SignedPreKeyPair?

    /**
     * Stores [preKey], created at [createdAt], and makes it current. The
     * previous current key stays available by ID; its
     * [SignedPreKeyInfo.replacedAt] becomes [createdAt].
     */
    suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair, createdAt: Instant)

    /** Metadata of the stored signed prekey [id], or `null` if it is not stored. */
    suspend fun signedPreKeyInfo(id: SignedPreKeyId): SignedPreKeyInfo?

    /** Metadata of all stored signed prekeys, ordered by ID. */
    suspend fun signedPreKeyInfos(): List<SignedPreKeyInfo>

    /**
     * Gives keys stored before milestone 7 their timestamps: a missing
     * [SignedPreKeyInfo.createdAt] becomes [at], and so does a missing
     * [SignedPreKeyInfo.replacedAt] of a key that is not current. Keys that
     * have timestamps are not changed.
     */
    suspend fun stampLegacySignedPreKeys(at: Instant)

    /**
     * Deletes the signed prekey [id], private key included. Throws
     * [IllegalArgumentException] for the current one. Deleting a key that is
     * not stored does nothing. The high-water mark is kept.
     */
    suspend fun removeSignedPreKey(id: SignedPreKeyId)

    suspend fun highestSignedPreKeyId(): SignedPreKeyId?

    suspend fun oneTimePreKey(id: OneTimePreKeyId): OneTimePreKeyPair?

    /** Public halves of all stored one-time prekeys, ordered by ID. */
    suspend fun publicOneTimePreKeys(): List<PublicOneTimePreKey>

    suspend fun oneTimePreKeyCount(): Int

    suspend fun storeOneTimePreKeys(preKeys: List<OneTimePreKeyPair>)

    /** Deletes a one-time prekey after a session was accepted with it. */
    suspend fun removeOneTimePreKey(id: OneTimePreKeyId)

    suspend fun highestOneTimePreKeyId(): OneTimePreKeyId?
}

/**
 * A sent application message the recipient has not acknowledged yet
 * (docs/message-reliability.md).
 *
 * @property sequence local send order, assigned by [PendingOutboundStore.store].
 *   Reliability metadata only; not a cryptographic value.
 * @property frame the encoded `SecurePayload.ApplicationMessage` (logical ID
 *   plus application plaintext). Every resend encrypts these bytes again.
 */
class PendingOutboundMessage(
    val recipient: DeviceAddress,
    val id: LogicalMessageId,
    val sequence: Long,
    val frame: ByteArray,
)

/**
 * Sent application messages kept until the recipient acknowledges them, so
 * they can be encrypted and sent again. Keyed by (recipient, logical ID).
 *
 * **Holds application plaintext** (encrypted at rest by persistent adapters,
 * see docs/storage-encryption.md). Entries are removed when the
 * acknowledgement arrives, never because the transport accepted an envelope.
 */
interface PendingOutboundStore {
    /**
     * Stores [frame] for [recipient] and returns its sequence number. Sequence
     * numbers increase with every call and are never reused, also after
     * removals and restarts. Throws [IllegalArgumentException] if [id] is
     * already pending for [recipient].
     */
    suspend fun store(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): Long

    suspend fun get(recipient: DeviceAddress, id: LogicalMessageId): PendingOutboundMessage?

    /** The messages pending for [recipient], in [PendingOutboundMessage.sequence] order. */
    suspend fun list(recipient: DeviceAddress): List<PendingOutboundMessage>

    /** Removes the entry; returns `false` if it was not pending. */
    suspend fun remove(recipient: DeviceAddress, id: LogicalMessageId): Boolean
}

/**
 * Logical messages already accepted from a remote device, for duplicate
 * suppression (docs/message-reliability.md). Keyed by (sender, logical ID):
 * the same ID from another sender is a different message. IDs are kept
 * forever; nothing here removes them.
 */
interface ProcessedInboundStore {
    suspend fun isProcessed(sender: DeviceAddress, id: LogicalMessageId): Boolean

    /** Records [id] from [sender]. Recording it again does nothing. */
    suspend fun markProcessed(sender: DeviceAddress, id: LogicalMessageId)
}

/**
 * Client storage boundary.
 *
 * [transaction] must be atomic: if [transaction]'s block throws, none of its
 * writes become visible; otherwise all of them do. Ratchet state is updated
 * together with the encrypt/decrypt work, and a consumed one-time prekey is
 * removed together with storing the session it created. A remote identity is
 * pinned in the same transaction that stores the first session with it. A
 * replaced session and the retired initiation are written together. A sent
 * message becomes pending together with the ratchet step that encrypted it; an
 * accepted message is marked processed together with the ratchet step that
 * decrypted it. An accepted identity change replaces the pin, removes the
 * session and retires its initiation together.
 *
 * Rules for the block:
 * - Use the receiver's stores, not those of the outer storage object.
 * - A nested `transaction` call on the receiver joins the running transaction.
 * - No network I/O or other long suspension: the transaction holds a lock.
 * - Do not switch threads. SQLite drivers bind a transaction to its thread.
 *
 * Store calls outside [transaction] act as single-call transactions.
 */
interface ClientStorage {
    val identity: IdentityStore
    val deviceAuthentication: DeviceAuthenticationKeyStore
    val remoteIdentities: RemoteIdentityStore
    val sessions: SessionStore
    val sessionInitiations: SessionInitiationStore
    val preKeys: PreKeyStore
    val pendingOutbound: PendingOutboundStore
    val processedInbound: ProcessedInboundStore

    suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T
}
