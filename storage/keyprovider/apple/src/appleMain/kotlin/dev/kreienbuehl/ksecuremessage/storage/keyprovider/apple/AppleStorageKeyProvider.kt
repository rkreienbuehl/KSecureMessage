package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * A [StorageKeyProvider] that keeps the storage key in the Apple Keychain
 * (docs/storage-key-providers.md).
 *
 * One generic password item per key: service
 * `dev.kreienbuehl.ksecuremessage.storage.<namespace>`, account
 * `v1/<key ID>`, data = the 32 raw key bytes. Items are in the data
 * protection keychain, accessible after the first unlock, this device only,
 * never synchronized. This is Keychain protection, not the Secure Enclave.
 *
 * [namespace] separates the keys of different databases, accounts or
 * profiles of one application (letters, digits, `.`, `_`, `-`; at most 64).
 * [accessGroup] is the keychain access group for sharing the key with app
 * extensions, or `null` for the application's default group.
 *
 * During a storage key rotation (docs/storage-key-rotation.md) there is one
 * item per key ID under the same service; [createKey] adds an item and never
 * updates one, [removeKey] deletes exactly one account's item.
 *
 * A lost key is never replaced: [key] returns `null`, and an encrypted
 * database fails to open.
 */
class AppleStorageKeyProvider internal constructor(
    namespace: String,
    accessGroup: String?,
    dataProtection: Boolean,
) : StorageKeyProvider {
    constructor(namespace: String = DEFAULT_NAMESPACE, accessGroup: String? = null) : this(namespace, accessGroup, dataProtection = true)

    init {
        require(NAMESPACE.matches(namespace)) { "Invalid storage key namespace" }
    }

    internal val keychain = Keychain(serviceName(namespace), accessGroup, dataProtection)

    override suspend fun loadOrCreateKey(): StorageEncryptionKey = keychainCall {
        creationLock.withLock {
            val ids = storedKeyIds()
            when (ids.size) {
                0 -> addAndRead(INITIAL_KEY_ID)
                1 -> readKey(ids.single()) ?: throw unavailable("Storage key disappeared from the Keychain")
                else -> throw unavailable("More than one storage key in the Keychain; the storage key is chosen by the database")
            }
        }
    }

    // Queries the item IDs only; any OSStatus except not-found throws KeyUnavailable like every other call.
    override suspend fun hasKeys(): Boolean = keychainCall { storedKeyIds().isNotEmpty() }

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = keychainCall { readKey(id) }

    override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey = keychainCall {
        creationLock.withLock {
            if (storedKeyIds().isEmpty()) throw unavailable("No storage key has been provisioned; a rotation key needs an existing key")
            readKey(id) ?: addAndRead(id)
        }
    }

    override suspend fun removeKey(id: StorageKeyId): Boolean = keychainCall {
        creationLock.withLock {
            val ids = storedKeyIds()
            if (id !in ids) return@withLock false
            check(ids.size > 1) { "The provider's last storage key cannot be removed" }
            // Only the item of this one account; never a query without an account.
            val removed = keychain.remove(account(id))
            if (readKey(id) != null) throw unavailable("Storage key ${id.value} was not removed from the Keychain")
            removed
        }
    }

    private fun storedKeyIds(): List<StorageKeyId> =
        keychain.accounts().map { account -> keyId(account) ?: throw unavailable("Unknown storage key item in the Keychain") }

    /** Adds item [id] unless it exists and returns the stored key, read back from the Keychain. */
    private fun addAndRead(id: StorageKeyId): StorageEncryptionKey {
        val created = StorageEncryptionKey.generate(id)
        val bytes = created.copyBytes()
        try {
            // Another process may have added the item meanwhile: then add
            // reports a duplicate, nothing is overwritten and the stored key wins.
            keychain.add(account(id), bytes)
        } finally {
            bytes.fill(0)
        }
        return readKey(id) ?: throw unavailable("Storage key was not persisted in the Keychain")
    }

    private fun readKey(id: StorageKeyId): StorageEncryptionKey? {
        val bytes = keychain.read(account(id)) ?: return null
        try {
            if (bytes.size != StorageEncryptionKey.SIZE) throw unavailable("Keychain storage key item has an invalid size")
            return StorageEncryptionKey(id, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private suspend fun <T> keychainCall(block: suspend () -> T): T = withContext(Dispatchers.IO) {
        try {
            block()
        } catch (e: KeychainException) {
            throw StorageEncryptionException.KeyUnavailable("Keychain storage key is not available (OSStatus ${e.status})", e)
        }
    }

    companion object {
        const val DEFAULT_NAMESPACE: String = "default"

        private const val SERVICE_PREFIX = "dev.kreienbuehl.ksecuremessage.storage."
        private const val ACCOUNT_PREFIX = "v1/"
        private val NAMESPACE = Regex("[A-Za-z0-9._-]{1,64}")
        private val INITIAL_KEY_ID = StorageKeyId(1)

        // Serializes creation and removal within the process; SecItemAdd's uniqueness of
        // service + account resolves races with other processes.
        private val creationLock = Mutex()

        internal fun serviceName(namespace: String): String = SERVICE_PREFIX + namespace

        internal fun account(id: StorageKeyId): String = ACCOUNT_PREFIX + id.value

        private fun keyId(account: String): StorageKeyId? =
            account.removePrefix(ACCOUNT_PREFIX).takeIf { account.startsWith(ACCOUNT_PREFIX) }?.toIntOrNull()?.takeIf { it >= 0 }?.let(::StorageKeyId)

        private fun unavailable(message: String) = StorageEncryptionException.KeyUnavailable(message)
    }
}
