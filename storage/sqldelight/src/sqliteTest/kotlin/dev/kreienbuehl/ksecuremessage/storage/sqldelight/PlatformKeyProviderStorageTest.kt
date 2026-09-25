package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.storage.encryption.StaticStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private val PUBLIC = ByteArray(32) { 0x21 }
private val SECRET = ByteArray(32) { 0x5A }

/**
 * [SqlDelightClientStorage.open] with a platform [StorageKeyProvider]
 * (docs/storage-key-providers.md): new, milestone 8 and encrypted
 * databases, and the provider states that must fail closed. Subclassed per
 * platform, over the real Keystore or Keychain.
 */
abstract class PlatformKeyProviderStorageTest {
    /** A new provider instance for [namespace]; two instances behave like an application restart. */
    protected abstract fun provider(namespace: String): StorageKeyProvider

    /** Removes the platform secret behind the provider state (Keystore key, Keychain item). */
    protected abstract fun loseBackingKey(namespace: String)

    /** Damages the provider state of [namespace]. */
    protected abstract fun corruptState(namespace: String)

    /** Deletes everything the provider stored for [namespace]. */
    protected abstract fun deleteProviderState(namespace: String)

    private val database = TestDatabase()
    private val namespace = "storage-${Random.nextLong().toULong()}"

    @AfterTest
    fun cleanUp() {
        database.close()
        deleteProviderState(namespace)
    }


    /** Opens the database file like an application start, with a new provider instance. */
    private suspend fun open(provider: StorageKeyProvider = provider(namespace)): SqlDelightClientStorage {
        database.closeOpenDrivers()
        return SqlDelightClientStorage.open(database.open(), provider)
    }

    private fun raw(): SqlDriver {
        database.closeOpenDrivers()
        return database.open()
    }

    private fun boundKeyId(): Long? = raw().longs("SELECT key_id FROM storage_encryption").single()

    private fun assertKeyNotStored(key: StorageEncryptionKey) {
        val hex = key.copyBytes().toHex()
        val stored = raw().dump().values.flatten().filterNotNull()
        assertTrue(stored.none { it.contains(hex, ignoreCase = true) }, "the raw storage key must not be in the database")
    }

    private suspend fun encryptedDatabase(): StorageEncryptionKey {
        open().identity.store(LocalIdentity(PUBLIC, SECRET))
        return assertNotNull(provider(namespace).key(StorageKeyId(boundKeyId()!!.toInt())))
    }

    /** The provider has no key other than [original] under its ID. */
    private suspend fun assertNotReplaced(original: StorageEncryptionKey?) {
        val found = try {
            provider(namespace).key(StorageKeyId(boundKeyId()!!.toInt()))
        } catch (_: StorageEncryptionException.KeyUnavailable) {
            null
        }
        if (found != null) assertContentEquals(original?.copyBytes(), found.copyBytes(), "no replacement key")
    }

    @Test
    fun newDatabaseKeepsItsKeyAcrossRestarts() = runTest {
        val key = encryptedDatabase()
        assertEquals(key.id.value.toLong(), boundKeyId())

        val identity = assertNotNull(open().identity.identity())
        assertContentEquals(SECRET, identity.privateKey)
        assertKeyNotStored(key)
    }

    @Test
    fun milestone8DatabaseIsEncryptedWithANewPlatformKey() = runTest {
        val old = database.open(Version5Schema)
        old.exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, ?, ?)", PUBLIC, SECRET)

        // No provider state yet: the provider creates the key, open encrypts.
        assertContentEquals(SECRET, open().identity.identity()?.privateKey)
        assertTrue(raw().blob("SELECT sealed_identity FROM local_identity").isSealed())
        val key = assertNotNull(provider(namespace).key(StorageKeyId(boundKeyId()!!.toInt())))

        // Restart: the same key opens it.
        assertContentEquals(SECRET, open().identity.identity()?.privateKey)
        assertKeyNotStored(key)
    }

    @Test
    fun encryptedDatabaseWithLostBackingKeyFailsClosed() = runTest {
        val key = encryptedDatabase()
        val before = raw().dump()
        loseBackingKey(namespace)

        repeat(2) {
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { open() }
        }
        assertEquals(before, raw().dump(), "the database is unchanged")
        assertNotReplaced(key)
    }

    @Test
    fun encryptedDatabaseWithCorruptProviderStateFailsClosed() = runTest {
        val key = encryptedDatabase()
        val before = raw().dump()
        corruptState(namespace)

        repeat(2) {
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { open() }
        }
        assertEquals(before, raw().dump())
        assertNotReplaced(key)
    }

    @Test
    fun databaseBoundToAnUnknownKeyIdCreatesNothing() = runTest {
        val foreign = StorageEncryptionKey(StorageKeyId(7), ByteArray(32) { 0x44 })
        open(StaticStorageKeyProvider(foreign)).identity.store(LocalIdentity(PUBLIC, SECRET))

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { open() }
        assertEquals(7L, boundKeyId())
        // Opening an encrypted database only looks keys up; the provider still has none.
        for (id in listOf(StorageKeyId(1), StorageKeyId(7))) {
            assertEquals(null, provider(namespace).key(id))
        }
    }
}
