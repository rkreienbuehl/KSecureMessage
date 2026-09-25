package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * The plain (unsigned, unentitled) test process: the default provider fails
 * closed. On macOS the data protection keychain rejects writes with -34018;
 * the iOS simulator test runner has no keychain (-25291). Not run by the
 * signed host.
 */
class KeychainWithoutEntitlementTest {
    private val namespace = "no-entitlement-${Random.nextLong().toULong()}"

    // Nothing should exist; remove what a broken provider might have written (macOS legacy keychain).
    @AfterTest
    fun deleteState() {
        try {
            AppleStorageKeyProvider(namespace, accessGroup = null, dataProtection = false).keychain.delete()
        } catch (_: KeychainException) {
            // iOS simulator runner: no keychain at all.
        }
    }

    @Test
    fun defaultProviderFailsClosed() = runTest {
        repeat(2) {
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { AppleStorageKeyProvider(namespace).loadOrCreateKey() }
            // Lookups without the entitlement may answer "not found" (macOS) instead
            // of failing: no key either way, so an encrypted database fails to open.
            val found = try {
                AppleStorageKeyProvider(namespace).key(StorageKeyId(1))
            } catch (_: StorageEncryptionException.KeyUnavailable) {
                null
            }
            assertNull(found)
        }
    }
}
