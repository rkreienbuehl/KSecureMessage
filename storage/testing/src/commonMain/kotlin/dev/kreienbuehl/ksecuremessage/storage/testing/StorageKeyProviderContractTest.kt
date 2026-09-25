package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

/**
 * Behavior every persistent [StorageKeyProvider] must have
 * (docs/storage-key-providers.md). Subclass it in a platform provider's
 * tests. Each test uses fresh random namespaces and deletes their state
 * afterwards, since platform key stores outlive the test process. Run it
 * only where the platform store is usable: it fails otherwise, never skips.
 */
abstract class StorageKeyProviderContractTest {
    /**
     * A new provider instance for [namespace] over the persistent platform
     * store. Two instances for one namespace behave like an application
     * restart.
     */
    protected abstract fun provider(namespace: String): StorageKeyProvider

    /** Removes the platform secret the provider state depends on (Keystore wrapping key, Keychain item). */
    protected abstract fun loseBackingKey(namespace: String)

    /** Damages the persisted provider state of [namespace] so it can no longer yield the key. */
    protected abstract fun corruptState(namespace: String)

    /** Deletes everything the provider stored for [namespace]. Tests only. */
    protected abstract fun deleteTestState(namespace: String)

    /**
     * Whether provider state remains after [loseBackingKey], so the provider
     * can tell "never created" from "lost" (Android: the wrapped key file
     * remains). Without it, only the encrypted database's bound key ID
     * prevents a replacement.
     */
    protected abstract val lossKeepsDetectableState: Boolean

    private val namespace = "contract-${Random.nextLong().toULong()}"
    private val otherNamespace = "$namespace-other"

    @AfterTest
    fun deleteState() {
        deleteTestState(namespace)
        deleteTestState(otherNamespace)
    }


    @Test
    fun firstLoadCreatesA32ByteKey() = runTest {
        val key = provider(namespace).loadOrCreateKey()
        assertEquals(StorageEncryptionKey.SIZE, key.copyBytes().size)
    }

    @Test
    fun loadOrCreateKeyIsIdempotent() = runTest {
        val provider = provider(namespace)
        val first = provider.loadOrCreateKey()
        val second = provider.loadOrCreateKey()
        assertSameKey(first, second)
    }

    @Test
    fun keyReturnsTheCreatedKey() = runTest {
        val provider = provider(namespace)
        val created = provider.loadOrCreateKey()
        assertSameKey(created, provider.key(created.id))
    }

    @Test
    fun restartedProviderReturnsTheSameKey() = runTest {
        val created = provider(namespace).loadOrCreateKey()
        assertSameKey(created, provider(namespace).key(created.id))
        assertSameKey(created, provider(namespace).loadOrCreateKey())
    }

    @Test
    fun unknownKeyIdIsNotReturnedAndCreatesNothing() = runTest {
        val provider = provider(namespace)
        assertNull(provider.key(StorageKeyId(1)), "no key before creation")
        assertNull(provider(namespace).key(StorageKeyId(1)), "key() created nothing")

        val created = provider.loadOrCreateKey()
        val unknown = StorageKeyId(created.id.value + 1000)
        assertNull(provider.key(unknown))
        assertNull(provider(namespace).key(unknown))
        assertSameKey(created, provider(namespace).loadOrCreateKey())
    }

    @Test
    fun namespacesHaveSeparateKeys() = runTest {
        val a = provider(namespace).loadOrCreateKey()
        assertNull(provider(otherNamespace).key(a.id), "another namespace has no key before creating one")

        val b = provider(otherNamespace).loadOrCreateKey()
        assertFalse(a.copyBytes().contentEquals(b.copyBytes()))
        assertSameKey(a, provider(namespace).loadOrCreateKey())
        assertSameKey(b, provider(otherNamespace).key(b.id))
    }

    @Test
    fun lostBackingKeyIsNeverReplaced() = runTest {
        val created = provider(namespace).loadOrCreateKey()
        loseBackingKey(namespace)

        assertNoOtherKey(created, provider(namespace))
        if (lossKeepsDetectableState) {
            repeat(2) {
                assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider(namespace).loadOrCreateKey() }
            }
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider(namespace).key(created.id) }
        }
    }

    @Test
    fun corruptStateFailsClosed() = runTest {
        val created = provider(namespace).loadOrCreateKey()
        corruptState(namespace)

        // Twice: a failed attempt must not have repaired or replaced the state.
        repeat(2) {
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider(namespace).key(created.id) }
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider(namespace).loadOrCreateKey() }
        }
    }

    @Test
    fun concurrentFirstCreationYieldsOneKey() = runTest {
        val keys = withContext(Dispatchers.Default) {
            (1..16).map { async { provider(namespace).loadOrCreateKey() } }.awaitAll()
        }
        keys.forEach { assertSameKey(keys.first(), it) }
        assertSameKey(keys.first(), provider(namespace).key(keys.first().id))
    }

    private suspend fun assertNoOtherKey(original: StorageEncryptionKey, provider: StorageKeyProvider) {
        val found = try {
            provider.key(original.id)
        } catch (_: StorageEncryptionException.KeyUnavailable) {
            null
        }
        if (found != null) assertSameKey(original, found)
    }

    private fun assertSameKey(expected: StorageEncryptionKey, actual: StorageEncryptionKey?) {
        assertEquals(expected.id, actual?.id)
        assertContentEquals(expected.copyBytes(), actual?.copyBytes())
    }
}
