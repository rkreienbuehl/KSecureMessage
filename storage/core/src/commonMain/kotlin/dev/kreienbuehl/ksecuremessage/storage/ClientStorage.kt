package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PublicOneTimePreKey
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair

// Every store below except RemoteIdentityStore and SessionInitiationStore holds secret key material or
// ratchet state as raw bytes.
// Adapters persist those bytes as they are; none of them encrypts at rest.
// Protect the underlying database or files with platform means.
// See docs/storage.md.

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
 * Remote identity keys pinned on first contact (trust on first use, see
 * docs/identity-trust.md). One public identity key per remote [DeviceAddress];
 * two devices of the same user have separate entries.
 *
 * Keys are public, but a pin is security state: it is only ever added, never
 * replaced or removed here. The client pins a key only after the first
 * contact with it succeeded cryptographically.
 */
interface RemoteIdentityStore {
    suspend fun identityKey(address: DeviceAddress): ByteArray?

    /**
     * Pins [identityKey] for [address]. Storing the key that is already
     * pinned does nothing. Throws [IllegalStateException] if a different key
     * is pinned: a pin is never replaced silently.
     */
    suspend fun store(address: DeviceAddress, identityKey: ByteArray)
}

/**
 * Session initiations from a remote device that must never become the current
 * session again (see docs/session-lifecycle.md): initiations whose session
 * was replaced, and initiations that lost a simultaneous-initiation collision.
 * Kept per remote [DeviceAddress]. IDs are public values.
 *
 * Entries are only ever added, never removed here. The client retires an ID
 * in the same transaction that replaces the session or rejects the
 * initiation, so the entry survives restarts together with that decision.
 */
interface SessionInitiationStore {
    suspend fun isRetired(remote: DeviceAddress, id: SessionInitiationId): Boolean

    /** Retires [id] for [remote]. Retiring an ID twice does nothing. */
    suspend fun retire(remote: DeviceAddress, id: SessionInitiationId)
}

/**
 * The local device's private prekeys.
 *
 * Signed prekeys are never deleted here: an incoming `PreKeyMessage` may
 * still name an older one after [storeCurrentSignedPreKey] replaced it.
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

    /** Stores [preKey] and makes it current. The previous one stays available by ID. */
    suspend fun storeCurrentSignedPreKey(preKey: SignedPreKeyPair)

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
 * Client storage boundary.
 *
 * [transaction] must be atomic: if [transaction]'s block throws, none of its
 * writes become visible; otherwise all of them do. Ratchet state is updated
 * together with the encrypt/decrypt work, and a consumed one-time prekey is
 * removed together with storing the session it created. A remote identity is
 * pinned in the same transaction that stores the first session with it. A
 * replaced session and the retired initiation are written together.
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
    val remoteIdentities: RemoteIdentityStore
    val sessions: SessionStore
    val sessionInitiations: SessionInitiationStore
    val preKeys: PreKeyStore

    suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T
}
