package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * A [StorageKeyProvider] over a key store that outlives provider instances,
 * like a platform key store across application restarts, held in memory
 * for tests. Hooks simulate crashes right after a provider change was
 * persisted and failures before one.
 */
class MemoryKeyStore {
    internal val mutex = Mutex()
    internal val keys = mutableMapOf<String, MutableMap<StorageKeyId, StorageEncryptionKey>>()

    /** Throws after [StorageKeyProvider.createKey] persisted the key: a crash before the caller saw it. */
    var crashAfterCreate = false

    /** Throws after [StorageKeyProvider.removeKey] removed the key. */
    var crashAfterRemove = false

    /** Namespaces whose state is damaged: every call fails. */
    val corrupted = mutableSetOf<String>()

    /** Makes [StorageKeyProvider.createKey] fail before creating anything. */
    var failCreate = false

    /** Makes [StorageKeyProvider.removeKey] fail before removing anything. */
    var failRemove = false

    fun provider(namespace: String): StorageKeyProvider = MemoryStorageKeyProvider(this, namespace)

    /** Test-only: key material present for [namespace]. */
    fun ids(namespace: String): Set<StorageKeyId> = keys[namespace]?.keys?.toSet().orEmpty()

    /** Test-only: loses key [id] as a platform store could (not a provider operation). */
    fun lose(namespace: String, id: StorageKeyId) {
        keys[namespace]?.remove(id)
    }

    /** Test-only: puts key material directly, like a leftover item of an earlier install. */
    fun put(namespace: String, key: StorageEncryptionKey) {
        keys.getOrPut(namespace) { mutableMapOf() }[key.id] = key
    }

    fun delete(namespace: String) {
        keys.remove(namespace)
        corrupted.remove(namespace)
    }
}

class InjectedCrash(message: String) : IllegalStateException(message)

private class MemoryStorageKeyProvider(private val store: MemoryKeyStore, private val namespace: String) : StorageKeyProvider {
    private suspend fun <T> keys(block: MutableMap<StorageKeyId, StorageEncryptionKey>.() -> T): T =
        store.mutex.withLock {
            if (namespace in store.corrupted) throw StorageEncryptionException.KeyUnavailable("Damaged key store state")
            store.keys.getOrPut(namespace) { mutableMapOf() }.block()
        }

    override suspend fun loadOrCreateKey(): StorageEncryptionKey = keys {
        when (size) {
            0 -> StorageEncryptionKey.generate(StorageKeyId(1)).also { put(it.id, it) }
            1 -> values.single()
            else -> throw StorageEncryptionException.KeyUnavailable("More than one storage key")
        }
    }

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = keys { get(id) }

    override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey = keys {
        if (store.failCreate) throw StorageEncryptionException.KeyUnavailable("Injected key store failure")
        if (isEmpty()) throw StorageEncryptionException.KeyUnavailable("No storage key has been provisioned")
        val key = getOrPut(id) { StorageEncryptionKey.generate(id) }
        if (store.crashAfterCreate) throw InjectedCrash("Injected crash after creating storage key ${id.value}")
        key
    }

    override suspend fun removeKey(id: StorageKeyId): Boolean = keys {
        if (store.failRemove) throw StorageEncryptionException.KeyUnavailable("Injected key store failure")
        if (id !in this) return@keys false
        check(size > 1) { "The provider's last storage key cannot be removed" }
        remove(id)
        if (store.crashAfterRemove) throw InjectedCrash("Injected crash after removing storage key ${id.value}")
        true
    }
}
