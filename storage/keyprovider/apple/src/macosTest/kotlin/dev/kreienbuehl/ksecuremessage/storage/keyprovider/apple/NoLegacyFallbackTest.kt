package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Plain unsigned macOS test process: the default provider gets -34018 and
 * never falls back to the file-based keychain (which this process can use).
 */
class NoLegacyFallbackTest {
    private val namespace = "no-fallback-${Random.nextLong().toULong()}"
    private val service = AppleStorageKeyProvider.serviceName(namespace)

    @AfterTest
    fun deleteState() = AppleStorageKeyProvider.legacyFileKeychain(namespace).keychain.delete()

    @Test
    fun missingEntitlementDoesNotFallBackToTheLegacyKeychain() = runTest {
        val failure = assertFailsWith<StorageEncryptionException.KeyUnavailable> { AppleStorageKeyProvider(namespace).loadOrCreateKey() }
        assertTrue(failure.message!!.contains("OSStatus -34018"), failure.message)

        assertEquals(emptyList(), KeychainInspector.items(service, dataProtection = false))
        assertEquals(null, AppleStorageKeyProvider.legacyFileKeychain(namespace).key(StorageKeyId(1)))
    }
}

/**
 * Signed host, macOS: the default provider's item is in the data protection
 * keychain and not in the file-based one.
 */
class DataProtectionNotLegacyTest {
    private val namespace = "item-${Random.nextLong().toULong()}"
    private val service = AppleStorageKeyProvider.serviceName(namespace)

    @AfterTest
    fun deleteState() {
        AppleStorageKeyProvider(namespace).keychain.delete()
        AppleStorageKeyProvider.legacyFileKeychain(namespace).keychain.delete()
    }

    @Test
    fun itemIsInTheDataProtectionKeychainOnly() = runTest {
        AppleStorageKeyProvider(namespace).loadOrCreateKey()

        assertEquals(1, KeychainInspector.items(service, dataProtection = true).size)
        // Explicitly the file-based keychain only. (A query without
        // kSecUseDataProtectionKeychain, like legacyFileKeychain's, searches both
        // keychains in an entitled process and would find the item.)
        assertEquals(emptyList(), KeychainInspector.items(service, dataProtection = false))
    }
}
