package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage

/**
 * Creates and replenishes the local identity and prekeys. Keys come from the
 * [ProtocolEngine]; storage only persists them. Every function runs inside
 * the caller's [ClientStorage.transaction].
 *
 * Local state only: publishing keys to a server is not handled here.
 */
internal class PreKeyManager(
    private val protocol: ProtocolEngine,
    private val configuration: PreKeyConfiguration,
) {
    /**
     * Creates whatever is missing: the identity, a current signed prekey and
     * one-time prekeys up to the target. Existing state is kept, so calling
     * it again changes nothing unless one-time prekeys were consumed.
     */
    suspend fun ClientStorage.ensureInitialized() {
        val localIdentity = identity.identity() ?: createIdentity()
        if (preKeys.currentSignedPreKey() == null) createSignedPreKey(localIdentity)

        val missing = configuration.oneTimePreKeyTarget - preKeys.oneTimePreKeyCount()
        if (missing > 0) {
            val firstId = nextId(preKeys.highestOneTimePreKeyId()?.value, missing, "one-time prekey")
            preKeys.storeOneTimePreKeys(protocol.createOneTimePreKeys(OneTimePreKeyId(firstId), missing))
        }
    }

    /** Replaces the current signed prekey. The old one stays stored for in-flight messages. */
    suspend fun ClientStorage.rotateSignedPreKey(): SignedPreKeyPair = createSignedPreKey(requireIdentity())

    private suspend fun ClientStorage.createIdentity(): LocalIdentity {
        // Prekeys without an identity mean lost or damaged storage. A new
        // identity would not match the stored prekeys and sessions.
        if (preKeys.highestSignedPreKeyId() != null || preKeys.highestOneTimePreKeyId() != null) {
            throw SecureMessageClientException.InconsistentStorage("Prekeys are stored but the local identity is missing")
        }
        return protocol.createIdentity().also { identity.store(it) }
    }

    private suspend fun ClientStorage.createSignedPreKey(identity: LocalIdentity): SignedPreKeyPair {
        val id = nextId(preKeys.highestSignedPreKeyId()?.value, 1, "signed prekey")
        return protocol.createSignedPreKey(identity, SignedPreKeyId(id)).also { preKeys.storeCurrentSignedPreKey(it) }
    }

    /** First of [count] unused IDs above [highest]. Fails instead of wrapping past `Int.MAX_VALUE`. */
    private fun nextId(highest: Int?, count: Int, kind: String): Int {
        val first = (highest ?: -1).toLong() + 1
        if (first + count - 1 > Int.MAX_VALUE) throw SecureMessageClientException.PreKeyIdsExhausted(kind)
        return first.toInt()
    }
}

/** Loads the local identity, which [SecureMessageClient.initialize] must have created. */
internal suspend fun ClientStorage.requireIdentity(): LocalIdentity =
    identity.identity() ?: throw SecureMessageClientException.NotInitialized()
