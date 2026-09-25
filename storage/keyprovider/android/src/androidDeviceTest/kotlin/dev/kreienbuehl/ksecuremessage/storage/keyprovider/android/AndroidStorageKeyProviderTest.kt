package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlinx.coroutines.test.runTest
import java.security.KeyStore
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Android specifics beyond the shared contract. */
class AndroidStorageKeyProviderTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val namespace = "android-${Random.nextLong().toULong()}"
    private val otherNamespace = "$namespace-other"

    @AfterTest
    fun deleteState() {
        for (name in listOf(namespace, otherNamespace)) {
            val provider = AndroidStorageKeyProvider(context, name)
            deleteAlias(provider.alias)
            provider.file.parentFile?.listFiles { file -> file.name.startsWith("storage-key-$name.") }?.forEach { it.delete() }
        }
    }

    @Test
    fun fileHoldsOnlyTheWrappedKey() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        val key = provider.loadOrCreateKey()
        val file = provider.file.readBytes()
        val raw = key.copyBytes()
        assertFalse(file.asList().windowed(raw.size).any { it == raw.asList() }, "raw storage key must not be in the file")

        val state = WrappedKeyFile.decode(file)
        assertEquals(provider.alias, state.alias)
        assertEquals(key.id, state.currentKeyId)
        assertTrue(provider.file.path.startsWith(context.noBackupFilesDir.path), "file is excluded from Auto Backup")
    }

    @Test
    fun keystoreKeyIsNotExportable() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        provider.loadOrCreateKey()
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(provider.alias, null)
        assertEquals(null, key.encoded, "Keystore keys never reveal their bytes")
    }

    @Test
    fun missingAliasLeavesFileUntouched() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        provider.loadOrCreateKey()
        val before = provider.file.readBytes()
        deleteAlias(provider.alias)

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.loadOrCreateKey() }
        assertContentEquals(before, provider.file.readBytes())
        assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(provider.alias), "no replacement wrapping key")
    }

    @Test
    fun wrappedKeyCopiedToAnotherNamespaceDoesNotUnwrap() = runTest {
        val a = AndroidStorageKeyProvider(context, namespace)
        val b = AndroidStorageKeyProvider(context, otherNamespace)
        a.loadOrCreateKey()
        b.loadOrCreateKey()
        // B's file names B's alias, so rewrite A's entry into it: only the associated data differs.
        val stateA = WrappedKeyFile.decode(a.file.readBytes())
        b.file.writeBytes(WrappedKeyFile(b.alias, stateA.currentKeyId, stateA.entries).encode())

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { b.loadOrCreateKey() }
    }

    @Test
    fun leftoverKeystoreKeyWithoutFileIsReused() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        provider.loadOrCreateKey()
        provider.file.delete() // as if creation stopped before the file was written

        val key = AndroidStorageKeyProvider(context, namespace).loadOrCreateKey()
        assertContentEquals(key.copyBytes(), AndroidStorageKeyProvider(context, namespace).key(key.id)!!.copyBytes())
    }

    @Test
    fun rotationKeysAreWrappedEntriesOfOneFile() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        val first = provider.loadOrCreateKey()
        val second = provider.createKey(StorageKeyId(2))
        val file = provider.file.readBytes()
        for (key in listOf(first, second)) {
            val raw = key.copyBytes()
            assertFalse(file.asList().windowed(raw.size).any { it == raw.asList() }, "raw storage key must not be in the file")
        }
        val state = WrappedKeyFile.decode(file)
        assertEquals(listOf(1, 2), state.entries.map { it.keyId.value })
        assertEquals(StorageKeyId(1), state.currentKeyId, "the file's current ID is the lowest entry, not rotation state")

        assertTrue(provider.removeKey(first.id))
        val after = WrappedKeyFile.decode(provider.file.readBytes())
        assertEquals(listOf(2), after.entries.map { it.keyId.value })
        assertEquals(StorageKeyId(2), after.currentKeyId)
        assertContentEquals(state.entry(StorageKeyId(2))!!.ciphertext, after.entry(StorageKeyId(2))!!.ciphertext, "other entries are kept byte for byte")
    }

    @Test
    fun damagedEntryFailsOnlyForItsKeyAndIsNeverRegenerated() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        provider.loadOrCreateKey()
        val second = provider.createKey(StorageKeyId(2))
        val state = WrappedKeyFile.decode(provider.file.readBytes())
        val damaged = state.entry(StorageKeyId(1))!!.let { entry ->
            WrappedKeyFile.Entry(entry.keyId, entry.iv, entry.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() })
        }
        provider.file.writeBytes(WrappedKeyFile(provider.alias, state.currentKeyId, listOf(damaged, state.entry(StorageKeyId(2))!!)).encode())

        repeat(2) {
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.key(StorageKeyId(1)) }
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.createKey(StorageKeyId(1)) }
        }
        assertContentEquals(second.copyBytes(), provider.key(StorageKeyId(2))!!.copyBytes())

        // Adding a key keeps the damaged entry as it is.
        provider.createKey(StorageKeyId(3))
        assertContentEquals(damaged.ciphertext, WrappedKeyFile.decode(provider.file.readBytes()).entry(StorageKeyId(1))!!.ciphertext)
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.key(StorageKeyId(1)) }
    }

    @Test
    fun createKeyWithMissingAliasChangesNothing() = runTest {
        val provider = AndroidStorageKeyProvider(context, namespace)
        provider.loadOrCreateKey()
        val before = provider.file.readBytes()
        deleteAlias(provider.alias)

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { provider.createKey(StorageKeyId(2)) }
        assertContentEquals(before, provider.file.readBytes())
        assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(provider.alias), "no replacement wrapping key")
        assertNull(WrappedKeyFile.decode(provider.file.readBytes()).entry(StorageKeyId(2)))
    }

    @Test
    fun namespaceIsValidated() {
        for (invalid in listOf("", "a/b", "../x", "a b", "x".repeat(65))) {
            assertFailsWith<IllegalArgumentException> { AndroidStorageKeyProvider(context, invalid) }
        }
    }
}
