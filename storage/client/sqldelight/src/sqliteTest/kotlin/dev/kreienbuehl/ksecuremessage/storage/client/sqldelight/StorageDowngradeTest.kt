package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.encryption.StaticStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

/** What an attacker with write access to the database file wants the device to adopt. */
private val ATTACKER_PUBLIC = ByteArray(64) { 0x41 }
private val ATTACKER_PRIVATE = ByteArray(32) { 0x42 }

/**
 * Storage encryption downgrade protection (S1, finding F7;
 * docs/storage-encryption.md, "Downgrade protection"). An attacker who can
 * write the database file sets storage_encryption.format back to 0 and puts
 * chosen plaintext rows in; the next open must not seal them with the
 * legitimate storage key.
 */
class StorageDowngradeTest {
    private val database = TestDatabase()
    private val keyStore = MemoryKeyStore()
    private val keys get() = keyStore.provider("device")
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() = database.close()

    private suspend fun reopen(provider: dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider = keys): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return SqlDelightClientStorage.open(driver, provider)
    }

    /** A normal encrypted installation: identity, device key, prekeys. */
    private suspend fun encryptedDatabase(): ByteArray {
        val storage = reopen()
        SecureMessageClient(BOB, storage, KodiumProtocolEngine(), TestRelay(), PreKeyConfiguration(oneTimePreKeyTarget = 2)).initialize()
        val identity = storage.identity.identity()!!
        database.closeOpenDrivers()
        driver = database.open()
        return identity.privateKey
    }

    /** The milestone 8 DDL of the tables the plaintext migration rebuilds, from the frozen schema. */
    private fun legacyDdl(): Map<String, String> {
        val scratch = TestDatabase()
        try {
            val old = scratch.open(Version5Schema)
            return listOf("local_identity", "signed_pre_key", "one_time_pre_key", "session", "pending_outbound_message")
                .associateWith { table -> old.strings("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '$table'").single()!! }
        } finally {
            scratch.close()
        }
    }

    /**
     * The full attack: turn the encrypted database back into a milestone 8
     * database holding the attacker's plaintext identity, as far as SQL can.
     */
    private fun SqlDriver.rewriteAsPlaintext(clearMarkers: Boolean = true, deletePostPlaintextRecords: Boolean = true) {
        val ddl = legacyDdl()
        exec("UPDATE storage_encryption SET format = 0")
        if (clearMarkers) exec("UPDATE storage_encryption SET key_id = NULL, key_check = NULL, highest_key_id = NULL")
        if (deletePostPlaintextRecords) exec("DELETE FROM device_authentication_key")
        exec("UPDATE pre_key_state SET current_signed_pre_key_id = NULL")
        for ((table, sql) in ddl) {
            exec("DROP TABLE $table")
            exec(sql)
        }
        exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, ?, ?)", ATTACKER_PUBLIC, ATTACKER_PRIVATE)
    }

    private fun assertNothingSealed(before: Map<String, List<String?>>) {
        assertEquals(before, driver.dump(), "nothing was migrated, sealed or cleared")
        assertEquals(listOf(0L), driver.longs("SELECT format FROM storage_encryption"))
        assertContentEquals(ATTACKER_PRIVATE, driver.blob("SELECT private_key FROM local_identity"), "the injected row is still plaintext")
    }

    @Test
    fun f7EncryptedDatabaseRewrittenAsPlaintextIsRejected() = runTest {
        val genuine = encryptedDatabase()
        driver.rewriteAsPlaintext()
        val before = driver.dump()

        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertNothingSealed(before)
        assertFalse(ATTACKER_PRIVATE.contentEquals(genuine))
        assertEquals(setOf(StorageKeyId(1)), keyStore.ids("device"), "no key created or removed")
    }

    @Test
    fun f7OnlyTheFormatMarkerFlippedIsRejectedTyped() = runTest {
        encryptedDatabase()
        driver.exec("UPDATE storage_encryption SET format = 0")
        val before = driver.dump()
        // The key columns still name the bound key: refused before touching any table (no raw SQL error).
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertEquals(before, driver.dump())
    }

    @Test
    fun f7MarkersClearedButPostPlaintextRecordsKeptIsRejected() = runTest {
        encryptedDatabase()
        driver.rewriteAsPlaintext(deletePostPlaintextRecords = false)
        val before = driver.dump()
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertNothingSealed(before)
    }

    @Test
    fun f7KeyColumnsOnlyClearedIsRejected() = runTest {
        encryptedDatabase()
        driver.exec("UPDATE storage_encryption SET format = 0, key_id = NULL, key_check = NULL, highest_key_id = NULL")
        driver.exec("DELETE FROM device_authentication_key")
        val before = driver.dump()
        // The tables are still in the sealed layout.
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertEquals(before, driver.dump())
    }

    @Test
    fun f7FlippedDatabaseIsRejectedByItsStructureEvenWithAnEmptyProvider() = runTest {
        // The provider lost its state (or is a new namespace): only the database
        // itself can show that it was encrypted before.
        encryptedDatabase()
        keyStore.delete("device")
        driver.exec("UPDATE storage_encryption SET format = 0")
        var before = driver.dump()
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertEquals(before, driver.dump())
        // Markers cleared as well: the sealed table layout and the device key still give it away.
        driver.exec("UPDATE storage_encryption SET key_id = NULL, key_check = NULL, highest_key_id = NULL")
        before = driver.dump()
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertEquals(before, driver.dump())
        assertEquals(emptySet(), keyStore.ids("device"), "no key was created")
    }

    @Test
    fun f7ForgedMigrationIntentIsRejected() = runTest {
        encryptedDatabase()
        // The attacker holds records sealed with the real key: the key check and every sealed column.
        val keyCheck = driver.blob("SELECT key_check FROM storage_encryption")
        driver.rewriteAsPlaintext()
        for (forged in listOf(keyCheck, ByteArray(40) { 1 }, ClientRecordCipher(StorageEncryptionKey.generate(StorageKeyId(1))).sealMigrationIntent())) {
            driver.exec("UPDATE storage_encryption SET migration_intent = ?", forged)
            val before = driver.dump()
            assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
            assertNothingSealed(before)
        }
    }

    @Test
    fun f7CrashBetweenKeyCreationAndTheIntentFailsClosed() = runTest {
        // A genuine plaintext database whose provider already holds a key
        // without any intent is indistinguishable from a downgrade.
        database.open(Version5Schema).exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')")
        database.closeOpenDrivers()
        keyStore.put("device", StorageEncryptionKey.generate(StorageKeyId(1)))
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
        assertEquals(listOf(0L), driver.longs("SELECT format FROM storage_encryption"))
    }

    @Test
    fun f7StaticProviderCannotProveAFirstMigration() = runTest {
        // An application-held key may have been used before: a plaintext
        // database is only migrated with a provider that can show it is empty.
        database.open(Version5Schema).exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')")
        database.closeOpenDrivers()
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen(StaticStorageKeyProvider(TestKeys.A)) }
        assertEquals(listOf(0L), driver.longs("SELECT format FROM storage_encryption"))
    }

    @Test
    fun genuinePlaintextDatabaseMigratesWithAnEmptyProvider() = runTest {
        database.open(Version5Schema).exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')")
        database.closeOpenDrivers()
        val storage = reopen()
        assertContentEquals(byteArrayOf(3, 4), storage.identity.identity()?.privateKey)
        assertEquals(listOf(1L), driver.longs("SELECT format FROM storage_encryption"))
        assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM storage_encryption WHERE migration_intent IS NOT NULL"))
        assertTrue(driver.blob("SELECT sealed_identity FROM local_identity").isSealed())
        // Once migrated, turning it back is a downgrade.
        driver.rewriteAsPlaintext()
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
    }

    @Test
    fun encryptedDatabaseCarryingAnIntentIsRejected() = runTest {
        encryptedDatabase()
        driver.exec("UPDATE storage_encryption SET migration_intent = X'00'")
        assertFailsWith<StorageEncryptionException.DowngradeRejected> { reopen() }
    }

    @Test
    fun version15DatabaseGainsAnEmptyMigrationIntent() = runTest {
        encryptedDatabase()
        val beforeDowngrade = driver.dump()
        driver.dropVersion16Additions()
        driver.exec("PRAGMA user_version = 15")
        val fixture = TestDatabase()
        try {
            val fixtureDriver = fixture.open(Version15Schema)
            assertEquals(fixtureDriver.tables().associateWith { fixtureDriver.columns(it) }, driver.tables().associateWith { driver.columns(it) })
            assertEquals(
                fixtureDriver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
                driver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"),
            )
        } finally {
            fixture.close()
        }
        val before = driver.dump()
        reopen()
        assertEquals(listOf(16L), driver.longs("PRAGMA user_version"))
        assertEquals(before.withEmptyMigrationIntent(), driver.dump(), "no row changes")
        assertEquals(beforeDowngrade, driver.dump())
    }
}
