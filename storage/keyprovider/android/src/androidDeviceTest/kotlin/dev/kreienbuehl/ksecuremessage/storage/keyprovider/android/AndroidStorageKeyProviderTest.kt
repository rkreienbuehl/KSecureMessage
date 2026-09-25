package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import kotlinx.coroutines.test.runTest
import java.security.KeyStore
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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
    fun namespaceIsValidated() {
        for (invalid in listOf("", "a/b", "../x", "a b", "x".repeat(65))) {
            assertFailsWith<IllegalArgumentException> { AndroidStorageKeyProvider(context, invalid) }
        }
    }
}
