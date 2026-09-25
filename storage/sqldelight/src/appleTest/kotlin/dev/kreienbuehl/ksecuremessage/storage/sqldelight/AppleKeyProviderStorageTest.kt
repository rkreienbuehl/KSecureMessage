package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple.AppleStorageKeyProvider

/**
 * Storage with the default (data protection keychain) provider. Skipped
 * where the test process has no keychain entitlements: macOS test binaries
 * and the iOS simulator runner.
 */
class AppleKeyProviderStorageTest : KeychainStorageTest(dataProtection = true) {
    override fun provider(namespace: String): StorageKeyProvider = AppleStorageKeyProvider(namespace)
}
