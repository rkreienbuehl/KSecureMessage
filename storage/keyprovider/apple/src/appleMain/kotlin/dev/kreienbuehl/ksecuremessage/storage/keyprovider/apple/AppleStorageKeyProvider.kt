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
            val ids = keychain.accounts().map { account -> keyId(account) ?: throw unavailable("Unknown storage key item in the Keychain") }
            when (ids.size) {
                0 -> {
                    val created = StorageEncryptionKey.generate(INITIAL_KEY_ID)
                    val bytes = created.copyBytes()
                    try {
                        // Another process may have added the item meanwhile: then
                        // add reports a duplicate and the stored key wins.
                        keychain.add(account(INITIAL_KEY_ID), bytes)
                    } finally {
                        bytes.fill(0)
                    }
                    // Only a key read back from the Keychain is returned.
                    readKey(INITIAL_KEY_ID) ?: throw unavailable("Storage key was not persisted in the Keychain")
                }
                1 -> readKey(ids.single()) ?: throw unavailable("Storage key disappeared from the Keychain")
                else -> throw unavailable("More than one storage key in the Keychain; key rotation is not supported yet")
            }
        }
    }

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = keychainCall { readKey(id) }

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

        // Serializes creation within the process; SecItemAdd's uniqueness of
        // service + account resolves races with other processes.
        private val creationLock = Mutex()

        internal fun serviceName(namespace: String): String = SERVICE_PREFIX + namespace

        internal fun account(id: StorageKeyId): String = ACCOUNT_PREFIX + id.value

        private fun keyId(account: String): StorageKeyId? =
            account.removePrefix(ACCOUNT_PREFIX).takeIf { account.startsWith(ACCOUNT_PREFIX) }?.toIntOrNull()?.takeIf { it >= 0 }?.let(::StorageKeyId)

        private fun unavailable(message: String) = StorageEncryptionException.KeyUnavailable(message)
    }
}
