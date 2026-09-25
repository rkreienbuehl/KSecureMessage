package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.testing.StorageKeyProviderContractTest

/**
 * The contract on the data protection keychain, as applications use it.
 * Needs a process with keychain entitlements: bare Kotlin/Native test
 * binaries have none on macOS (errSecMissingEntitlement, -34018) and no
 * keychain at all in the iOS simulator (errSecNotAvailable, -25291). There
 * the tests report themselves as skipped.
 */
class AppleStorageKeyProviderContractTest : AppleContractBase(dataProtection = true)

abstract class AppleContractBase(private val dataProtection: Boolean) : StorageKeyProviderContractTest() {
    private fun apple(namespace: String) = AppleStorageKeyProvider(namespace, accessGroup = null, dataProtection = dataProtection)

    override fun provider(namespace: String): StorageKeyProvider = apple(namespace)

    // The Keychain item is the whole provider state.
    override fun loseBackingKey(namespace: String) = apple(namespace).keychain.delete()

    override fun corruptState(namespace: String) =
        apple(namespace).keychain.update(AppleStorageKeyProvider.account(StorageKeyId(1)), ByteArray(31) { 7 })

    override fun deleteTestState(namespace: String) = apple(namespace).keychain.delete()

    override val lossKeepsDetectableState: Boolean = false

    override fun unavailableReason(): String? = keychainUnavailableReason(dataProtection)
}

// A lookup can report "not found" where writes fail, so probe with a write.
internal fun keychainUnavailableReason(dataProtection: Boolean): String? = try {
    Keychain(AppleStorageKeyProvider.serviceName("availability-probe"), null, dataProtection).delete()
    null
} catch (e: KeychainException) {
    "keychain not usable by this test process (OSStatus ${e.status})"
}
