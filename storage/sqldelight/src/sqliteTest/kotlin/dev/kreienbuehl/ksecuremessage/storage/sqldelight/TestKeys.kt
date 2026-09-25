package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.encryption.StaticStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider

/** Fixed storage keys for tests. Never generated randomly, so failures reproduce. */
object TestKeys {
    val A = StorageEncryptionKey(StorageKeyId(1), ByteArray(32) { (0x10 + it).toByte() })

    /** Same key ID as [A], other bytes: the wrong key. */
    val B = StorageEncryptionKey(StorageKeyId(1), ByteArray(32) { (0x70 + it).toByte() })

    /** Another key ID. */
    val C = StorageEncryptionKey(StorageKeyId(2), ByteArray(32) { (0x30 + it).toByte() })

    val providerA: StorageKeyProvider = StaticStorageKeyProvider(A)

    /** Has no key at all: every call fails. */
    val missing: StorageKeyProvider = object : StorageKeyProvider {
        override suspend fun loadOrCreateKey(): StorageEncryptionKey = error("No key in the key store")
        override suspend fun key(id: StorageKeyId): StorageEncryptionKey? = null
        override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey = error("No key in the key store")
        override suspend fun removeKey(id: StorageKeyId): Boolean = false
    }
}

suspend fun openStorage(driver: SqlDriver, keyProvider: StorageKeyProvider = TestKeys.providerA): SqlDelightClientStorage =
    SqlDelightClientStorage.open(driver, keyProvider)
