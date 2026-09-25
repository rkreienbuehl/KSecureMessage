package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.testing.StorageKeyProviderContractTest
import java.security.KeyStore

/** The contract on the real Android Keystore of the device or emulator. */
class AndroidStorageKeyProviderContractTest : StorageKeyProviderContractTest() {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun android(namespace: String) = AndroidStorageKeyProvider(context, namespace)

    override fun provider(namespace: String): StorageKeyProvider = android(namespace)

    override fun loseBackingKey(namespace: String) = deleteAlias(android(namespace).alias)

    override fun corruptState(namespace: String) {
        val file = android(namespace).file
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte() // the GCM tag
        file.writeBytes(bytes)
    }

    override fun deleteTestState(namespace: String) {
        val provider = android(namespace)
        deleteAlias(provider.alias)
        provider.file.parentFile?.listFiles { file -> file.name.startsWith("storage-key-$namespace.") }?.forEach { it.delete() }
    }

    override val lossKeepsDetectableState: Boolean = true
}

internal fun deleteAlias(alias: String) {
    KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
}
