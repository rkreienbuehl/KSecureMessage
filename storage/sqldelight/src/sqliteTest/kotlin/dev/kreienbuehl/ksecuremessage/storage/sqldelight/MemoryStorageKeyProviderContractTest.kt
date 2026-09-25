package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.testing.StorageKeyProviderContractTest

/** The provider contract on the in-memory test key store the rotation tests use. */
class MemoryStorageKeyProviderContractTest : StorageKeyProviderContractTest() {
    private val store = MemoryKeyStore()

    override fun provider(namespace: String): StorageKeyProvider = store.provider(namespace)

    override fun loseBackingKey(namespace: String) = store.delete(namespace)

    override fun corruptState(namespace: String) {
        store.corrupted += namespace
    }

    override fun deleteTestState(namespace: String) = store.delete(namespace)

    override val lossKeepsDetectableState: Boolean = false
}
