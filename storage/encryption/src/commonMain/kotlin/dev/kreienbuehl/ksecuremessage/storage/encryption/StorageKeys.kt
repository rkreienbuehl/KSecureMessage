package dev.kreienbuehl.ksecuremessage.storage.encryption

import kotlin.jvm.JvmInline

/**
 * Identifies a storage encryption key. Not secret: every encrypted record
 * carries the ID of the key that sealed it, so a future key can coexist with
 * this one during a re-encryption (docs/storage-encryption.md).
 */
@JvmInline
value class StorageKeyId(val value: Int) {
    init {
        require(value >= 0) { "Storage key ID must not be negative" }
    }
}

/**
 * A 256-bit key for record-level client storage encryption, with its [id].
 *
 * Belongs to its own cryptographic domain: never derive it from, or reuse it
 * as, an identity, prekey or session key. The bytes are copied in and out;
 * [toString] never shows them.
 */
class StorageEncryptionKey(val id: StorageKeyId, bytes: ByteArray) {
    private val value: ByteArray = bytes.copyOf()

    init {
        require(value.size == SIZE) { "Storage encryption key must have $SIZE bytes" }
    }

    /**
     * A copy of the key bytes, for a [StorageKeyProvider] that has to persist
     * the key in platform key storage. Wipe the copy after use.
     */
    fun copyBytes(): ByteArray = value.copyOf()

    override fun toString(): String = "StorageEncryptionKey(id=${id.value}, key=<redacted>)"

    companion object {
        /** Key size in bytes (AES-256). */
        const val SIZE: Int = 32

        /** A new random key from the platform's cryptographic random source. */
        fun generate(id: StorageKeyId): StorageEncryptionKey {
            val bytes = secureRandomBytes(SIZE)
            return try {
                StorageEncryptionKey(id, bytes)
            } finally {
                bytes.fill(0)
            }
        }
    }
}

/**
 * Supplies storage encryption keys. Key storage is the provider's job, never
 * the database's: a key kept next to the records it protects protects
 * nothing. Platform providers (Android Keystore, Apple Keychain, an
 * application secret store) implement this interface.
 *
 * A provider holds key material only. Which key is current, and whether a
 * storage key rotation is running, is recorded in the database
 * (docs/storage-key-rotation.md); the database also allocates key IDs.
 *
 * A provider must never hand out a replacement for a key it lost: storage
 * that was encrypted before then fails closed (see [key]).
 */
interface StorageKeyProvider {
    /**
     * The key for storage that has no key bound yet: a new database, or a
     * database from before record encryption that is about to be encrypted.
     * Returns the provider's only key, or creates and persists key ID 1 if
     * the provider has none. Throws [StorageEncryptionException.KeyUnavailable]
     * if the provider holds several keys (its namespace belongs to a database
     * in or after a storage key rotation) or no key can be provided.
     */
    suspend fun loadOrCreateKey(): StorageEncryptionKey

    /**
     * The existing key [id], or `null` if the provider does not have it.
     * Never creates a key: this is called for storage that is already
     * encrypted with [id].
     */
    suspend fun key(id: StorageKeyId): StorageEncryptionKey?

    /**
     * Creates key [id] for a storage key rotation and returns it once it is
     * persisted and read back. If the provider already has key [id], returns
     * that key unchanged: a key is never overwritten or replaced, so a
     * repeated or concurrent call yields the same key. Other keys are not
     * touched. Throws [StorageEncryptionException.KeyUnavailable] if the
     * provider holds no key yet (rotation needs provisioned storage) or its
     * state cannot be read; nothing is changed then.
     */
    suspend fun createKey(id: StorageKeyId): StorageEncryptionKey

    /**
     * Removes key [id], for retiring a storage key after a rotation proved
     * that no record uses it. Returns `true` if this call removed it and
     * `false` if the provider did not have it. Other keys are not touched.
     * Throws [IllegalStateException] and changes nothing if [id] is the
     * provider's last key: a provider never removes all of its keys.
     */
    suspend fun removeKey(id: StorageKeyId): Boolean
}

/**
 * A [StorageKeyProvider] over keys the application already holds, for
 * example keys it loaded from its own secret store, and for tests.
 * [loadOrCreateKey] returns [current] and never creates a key; [createKey]
 * only returns a key that was passed in. [removeKey] forgets the key in this
 * instance; deleting its copy is up to the application. The keys only live
 * in memory; this class is not secure key storage.
 */
class StaticStorageKeyProvider(
    private val current: StorageEncryptionKey,
    vararg others: StorageEncryptionKey,
) : StorageKeyProvider {
    private val keys: MutableList<StorageEncryptionKey> = (listOf(current) + others).toMutableList()

    init {
        require(keys.map { it.id }.toSet().size == keys.size) { "Duplicate storage key ID" }
    }

    override suspend fun loadOrCreateKey(): StorageEncryptionKey = current

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = keys.firstOrNull { it.id == id }

    override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey =
        key(id) ?: throw StorageEncryptionException.KeyUnavailable("Storage key ${id.value} was not passed to this provider")

    override suspend fun removeKey(id: StorageKeyId): Boolean {
        val index = keys.indexOfFirst { it.id == id }
        if (index < 0) return false
        check(keys.size > 1) { "The provider's last storage key cannot be removed" }
        keys.removeAt(index)
        return true
    }
}
