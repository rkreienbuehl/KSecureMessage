package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.testing.StorageKeyProviderContractTest

/** The contract on the Keychain selected by [dataProtection], with [accessGroup] (`null`: the default group). */
abstract class AppleContractBase(
    private val dataProtection: Boolean,
    private val accessGroup: () -> String? = { null },
) : StorageKeyProviderContractTest() {
    private fun apple(namespace: String) = AppleStorageKeyProvider(namespace, accessGroup(), dataProtection)

    override fun provider(namespace: String): StorageKeyProvider = apple(namespace)

    // The Keychain item is the whole provider state.
    override fun loseBackingKey(namespace: String) = apple(namespace).keychain.delete()

    override fun corruptState(namespace: String) =
        apple(namespace).keychain.update(AppleStorageKeyProvider.account(StorageKeyId(1)), ByteArray(31) { 7 })

    override fun deleteTestState(namespace: String) = apple(namespace).keychain.delete()

    override val lossKeepsDetectableState: Boolean = false
}
