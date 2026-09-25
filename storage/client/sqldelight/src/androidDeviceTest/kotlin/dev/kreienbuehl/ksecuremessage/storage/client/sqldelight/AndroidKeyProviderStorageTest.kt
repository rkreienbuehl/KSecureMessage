package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import androidx.test.platform.app.InstrumentationRegistry
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.keyprovider.android.AndroidStorageKeyProvider
import java.io.File
import java.security.KeyStore

/**
 * Storage with the Android Keystore provider. Manipulates the Keystore alias
 * and wrapped key file by their documented names (docs/storage-key-providers.md).
 */
class AndroidKeyProviderStorageTest : PlatformKeyProviderStorageTest() {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun alias(namespace: String) = "dev.kreienbuehl.ksecuremessage.storage.v1.$namespace"

    private fun file(namespace: String) = File(context.noBackupFilesDir, "ksecuremessage/storage-key-$namespace.bin")

    override fun provider(namespace: String): StorageKeyProvider = AndroidStorageKeyProvider(context, namespace)

    override fun loseBackingKey(namespace: String) {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias(namespace))
    }

    override fun corruptState(namespace: String) {
        val bytes = file(namespace).readBytes()
        file(namespace).writeBytes(bytes.copyOf(bytes.size - 1))
    }

    override fun deleteProviderState(namespace: String) {
        loseBackingKey(namespace)
        File(context.noBackupFilesDir, "ksecuremessage").listFiles { f -> f.name.startsWith("storage-key-$namespace.") }?.forEach { it.delete() }
    }
}
