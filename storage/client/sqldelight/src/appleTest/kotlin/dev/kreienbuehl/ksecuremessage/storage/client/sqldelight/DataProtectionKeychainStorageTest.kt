package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.AppleStorageKeyProvider

/**
 * Storage with the default (data protection keychain) provider. Needs
 * keychain entitlements: runs only in the signed host
 * (`appleKeychainHostTest`); the plain test tasks exclude it.
 */
class DataProtectionKeychainStorageTest : KeychainStorageTest(dataProtection = true) {
    override fun provider(namespace: String): StorageKeyProvider = AppleStorageKeyProvider(namespace)
}
