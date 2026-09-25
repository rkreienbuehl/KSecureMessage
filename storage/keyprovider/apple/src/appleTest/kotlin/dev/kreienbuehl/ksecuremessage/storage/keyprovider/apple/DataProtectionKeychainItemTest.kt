package dev.kreienbuehl.ksecuremessage.storage.keyprovider.apple

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The item the default provider writes, as the Keychain reports it: data
 * protection keychain, documented service and account, "after first unlock,
 * this device only", not synchronizable, in the expected access group.
 * Signed host only.
 */
class DataProtectionKeychainItemTest {
    private val namespace = "item-${Random.nextLong().toULong()}"
    private val service = AppleStorageKeyProvider.serviceName(namespace)

    @AfterTest
    fun deleteState() {
        AppleStorageKeyProvider(namespace).keychain.delete()
    }

    @Test
    fun defaultProviderWritesTheDocumentedItem() = runTest {
        val key = AppleStorageKeyProvider(namespace).loadOrCreateKey()

        val item = KeychainInspector.items(service, dataProtection = true).single()
        assertEquals(KeychainItem(service, "v1/1", KeychainHost.defaultGroup, KeychainInspector.afterFirstUnlockThisDeviceOnly, synchronizable = false), item)
        assertEquals(StorageKeyId(1), key.id)
        assertEquals(StorageEncryptionKey.SIZE, AppleStorageKeyProvider(namespace).keychain.read("v1/1")?.also { it.fill(0) }?.size)
    }

    @Test
    fun explicitAccessGroupHoldsTheItem() = runTest {
        val shared = KeychainHost.sharedGroup
        AppleStorageKeyProvider(namespace, accessGroup = shared).loadOrCreateKey()

        assertEquals(listOf(shared), KeychainInspector.items(service, dataProtection = true).map { it.accessGroup })
        assertEquals(emptyList(), KeychainInspector.items(service, dataProtection = true, accessGroup = KeychainHost.defaultGroup))
        assertEquals(null, AppleStorageKeyProvider(namespace, accessGroup = KeychainHost.defaultGroup).key(StorageKeyId(1)))
    }

    @Test
    fun unentitledAccessGroupFailsWithoutRetryingElsewhere() = runTest {
        val provider = AppleStorageKeyProvider(namespace, accessGroup = KeychainHost.unentitledGroup)

        repeat(2) {
            val failure = assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.loadOrCreateKey() }
            assertTrue(failure.message!!.contains("OSStatus -34018"), failure.message)
        }
        // Not written to the default group (or anywhere else) instead.
        assertEquals(emptyList(), KeychainInspector.items(service, dataProtection = true))
    }

    @Test
    fun deletedItemIsNotRecreatedByLookups() = runTest {
        val provider = AppleStorageKeyProvider(namespace)
        val key = provider.loadOrCreateKey()
        provider.keychain.delete()

        assertEquals(null, AppleStorageKeyProvider(namespace).key(key.id))
        assertEquals(emptyList(), KeychainInspector.items(service, dataProtection = true))
    }
}

/**
 * Run by the host as its last launch: no provider item is left in this
 * host's data protection keychain groups. The host is a test application, so
 * every such item was written by a test.
 */
class DataProtectionLeftoverCheck {
    @Test
    fun noTestItemsRemain() {
        assertEquals(emptyList(), testItems().map { it.service }.distinct(), "test Keychain items left behind")
    }
}

/**
 * Deletes every provider item in this host's groups, after an interrupted
 * run (`<target>KeychainHostPurge`). Acts only with `KSM_KEYCHAIN_PURGE=yes`.
 */
class DataProtectionPurge {
    @Test
    fun deleteTestItems() {
        check(KeychainHost.purgeRequested) { "KSM_KEYCHAIN_PURGE=yes is not set: run through <target>KeychainHostPurge" }
        testItems().forEach { Keychain(it.service, it.accessGroup, dataProtection = true).delete() }
        assertEquals(emptyList(), testItems())
    }
}

private fun testItems(): List<KeychainItem> =
    KeychainInspector.items(null, dataProtection = true).filter { it.service.startsWith(AppleStorageKeyProvider.serviceName("")) }
