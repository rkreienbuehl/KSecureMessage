package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlin.coroutines.cancellation.CancellationException

/**
 * The storage key rotation state machine (docs/storage-key-rotation.md):
 * STABLE → PREPARING → MIGRATING → RETIRING → STABLE, over a [backend] that
 * persists the state and records and a [keyProvider] that holds the key
 * material.
 *
 * Order, each step committed before the next one starts:
 * allocate the key ID → provider creates the key and it is read back →
 * activate it → re-encryption batches → prove that no record uses the
 * retiring key and commit RETIRING → prove it again → remove the provider key
 * → STABLE. The storage never names a key the provider has not persisted, and
 * a key is never removed before the proof committed. Every step can be
 * interrupted and resumed. Provider keys the storage does not name as retiring
 * (for example one created by an abandoned start) are never removed.
 */
class StorageKeyRotationManager(
    private val backend: StorageKeyRotationBackend,
    private val keyProvider: StorageKeyProvider,
) {
    /** The rotation status. Key IDs only. */
    suspend fun status(): StorageKeyRotationStatus = backend.exclusive { currentStatus() }

    /**
     * Starts a rotation and returns the new current key ID. In PREPARING it
     * finishes the interrupted start with the key ID already allocated.
     * Throws [StorageKeyRotationInProgressException] while migrating or
     * retiring; [StorageEncryptionException.KeyIdsExhausted] if no key ID is
     * left; [StorageEncryptionException.KeyUnavailable] if the provider cannot
     * create or return the key (the storage then still uses its current key).
     */
    suspend fun rotate(): StorageKeyId = backend.exclusive {
        when (val state = backend.state()) {
            is StorageKeyRotationState.Stable -> backend.prepare(state, state.nextKeyId())
            is StorageKeyRotationState.Preparing -> Unit
            else -> throw StorageKeyRotationInProgressException(currentStatus())
        }
        activateNextKey()
    }

    /**
     * Advances a rotation by one bounded step and returns the new status:
     * PREPARING finishes the start like [rotate]; MIGRATING re-encrypts up to
     * [maxRecords] records and, when none are left, proves that no record uses
     * the retiring key and retires it; RETIRING removes the retiring key from
     * the provider (again) and ends the rotation; STABLE does nothing.
     */
    suspend fun resume(maxRecords: Int = DEFAULT_BATCH_SIZE): StorageKeyRotationStatus {
        require(maxRecords > 0) { "maxRecords must be positive" }
        return backend.exclusive {
            when (val state = backend.state()) {
                is StorageKeyRotationState.Preparing -> activateNextKey()
                is StorageKeyRotationState.Migrating -> if (backend.migrateBatch(state, maxRecords) == 0L) retire(state)
                is StorageKeyRotationState.Retiring -> finishRetirement()
                is StorageKeyRotationState.Stable -> Unit
            }
            currentStatus()
        }
    }

    private suspend fun currentStatus(): StorageKeyRotationStatus {
        val state = backend.state()
        return StorageKeyRotationStatus(
            phase = state.phase,
            currentKeyId = state.currentKeyId,
            nextKeyId = (state as? StorageKeyRotationState.Preparing)?.nextKeyId,
            retiringKeyId = when (state) {
                is StorageKeyRotationState.Migrating -> state.retiringKeyId
                is StorageKeyRotationState.Retiring -> state.retiringKeyId
                else -> null
            },
            remainingRecords = if (state is StorageKeyRotationState.Migrating) backend.remainingRecords() else 0,
        )
    }

    /** PREPARING to MIGRATING: the provider key first, durable and read back, then the storage. */
    /** Returns the activated key ID. */
    private suspend fun activateNextKey(): StorageKeyId {
        val state = backend.state()
        check(state is StorageKeyRotationState.Preparing) { "No storage key rotation is being prepared" }
        val id = state.nextKeyId
        val created = provide("Storage key ${id.value} could not be created") { keyProvider.createKey(id) }
        val loaded = provide("Storage key ${id.value} is not available after creating it") { keyProvider.key(id) }
        if (created.id != id || loaded.id != id || !sameKey(created, loaded)) {
            throw StorageEncryptionException.KeyUnavailable("Provider returned another storage key than ${id.value}")
        }
        backend.activate(state, loaded)
        return id
    }

    /** MIGRATING to RETIRING, committed only with the proof that no record uses another key. */
    private suspend fun retire(state: StorageKeyRotationState.Migrating) {
        backend.markRetiring(state) { references -> requireOnlyKey(state.currentKeyId, references) }
        finishRetirement()
    }

    /** RETIRING to STABLE: provider removal (repeatable), then the storage. */
    private suspend fun finishRetirement() {
        val state = backend.state()
        check(state is StorageKeyRotationState.Retiring) { "No storage key is being retired" }
        // Proven when RETIRING was entered; checked again before anything is deleted.
        requireOnlyKey(state.currentKeyId, backend.keyReferences())
        val retiring = state.retiringKeyId
        check(retiring != state.currentKeyId) { "The current storage key cannot be retired" }
        // false: already removed by an earlier attempt that stopped before the next step.
        try {
            keyProvider.removeKey(retiring)
        } catch (e: CancellationException) {
            throw e
        } catch (e: StorageEncryptionException) {
            throw e
        } catch (e: IllegalStateException) {
            throw e
        } catch (e: Exception) {
            throw StorageEncryptionException.KeyUnavailable("Storage key ${retiring.value} could not be removed", e)
        }
        backend.complete(state)
    }

    companion object {
        /** Records per [resume] call if not given. */
        const val DEFAULT_BATCH_SIZE: Int = 256

        /** Throws unless every sealed record in [references] names [keyId]. */
        private fun requireOnlyKey(keyId: StorageKeyId, references: Map<StorageKeyId, Long>) {
            val others = references.filter { (id, count) -> id != keyId && count > 0 }
            if (others.isNotEmpty()) {
                throw IllegalStateException("Sealed records still use storage keys ${others.keys.map { it.value }.sorted()}")
            }
        }

        private fun sameKey(a: StorageEncryptionKey, b: StorageEncryptionKey): Boolean {
            val x = a.copyBytes()
            val y = b.copyBytes()
            return try {
                x.contentEquals(y)
            } finally {
                x.fill(0)
                y.fill(0)
            }
        }

        private suspend fun provide(message: String, load: suspend () -> StorageEncryptionKey?): StorageEncryptionKey {
            val key = try {
                load()
            } catch (e: CancellationException) {
                throw e
            } catch (e: StorageEncryptionException) {
                throw e
            } catch (e: Exception) {
                throw StorageEncryptionException.KeyUnavailable(message, e)
            }
            return key ?: throw StorageEncryptionException.KeyUnavailable(message)
        }
    }
}
