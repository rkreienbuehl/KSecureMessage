package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.AppleStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.legacyFileKeychain

/** Storage with the macOS file-based keychain provider. */
class LegacyFileKeychainStorageTest : KeychainStorageTest(dataProtection = false) {
    override fun provider(namespace: String): StorageKeyProvider = AppleStorageKeyProvider.legacyFileKeychain(namespace)
}
