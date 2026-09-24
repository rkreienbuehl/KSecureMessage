package dev.kreienbuehl.ksecuremessage.storage

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair

interface SessionStore {
    suspend fun load(address: DeviceAddress): SecureSession?
    suspend fun store(session: SecureSession)
    suspend fun remove(address: DeviceAddress)
}

/**
 * The local device's private prekeys, looked up by the IDs in an incoming
 * `PreKeyMessage`. Holds private key material, so implementations must use
 * protected storage.
 *
 * Only what receiving a first-contact message needs: lookup and one-time
 * prekey removal. Generation, publication and rotation are not part of this
 * interface yet.
 */
interface PreKeyStore {
    suspend fun signedPreKey(id: SignedPreKeyId): SignedPreKeyPair?
    suspend fun oneTimePreKey(id: OneTimePreKeyId): OneTimePreKeyPair?

    /** Deletes a one-time prekey after a session was accepted with it. */
    suspend fun removeOneTimePreKey(id: OneTimePreKeyId)
}

/**
 * Client storage boundary. The transaction method is intentionally explicit:
 * ratchet state must be updated atomically with successful encrypt/decrypt work,
 * and a consumed one-time prekey must be removed together with storing the
 * session it created.
 */
interface ClientStorage {
    val sessions: SessionStore
    val preKeys: PreKeyStore

    suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T
}
