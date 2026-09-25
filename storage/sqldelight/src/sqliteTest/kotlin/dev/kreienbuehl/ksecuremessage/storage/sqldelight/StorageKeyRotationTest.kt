package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.StaticStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationInProgressException
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationStatus
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.messageId
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))
private val DAVE = DeviceAddress(UserId("dave"), DeviceId("desktop"))

private val K1 = StorageKeyId(1)
private val K2 = StorageKeyId(2)
private val K3 = StorageKeyId(3)

/** Sealed records written by [StorageKeyRotationTest.populate], without the key checks. */
private const val POPULATED_RECORDS = 10L

/** Storage key rotation of SQLDelight storage (docs/storage-key-rotation.md), checked on the persisted bytes. */
class StorageKeyRotationTest {
    private val database = TestDatabase()
    private val keys = MemoryKeyStore()
    private val namespace = "rotation"
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() = database.close()

    /** Opens the database file like an application start, with a new provider instance. */
    private suspend fun open(
        provider: StorageKeyProvider = keys.provider(namespace),
        records: MutableList<FailingRecords>? = null,
    ): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return if (records == null) {
            SqlDelightClientStorage.open(driver, provider)
        } else {
            SqlDelightClientStorage.open(driver, provider, FailingRecords.factory(records))
        }
    }

    private fun raw(): SqlDriver {
        database.closeOpenDrivers()
        return database.open().also { driver = it }
    }

    private fun spk(id: Int) =
        SignedPreKeyPair(SignedPreKeyId(id), ByteArray(32) { (id + 1).toByte() }, ByteArray(64) { 0x33 }, ByteArray(32) { (0x60 + id).toByte() })

    private fun otpk(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), ByteArray(32) { (id + 2).toByte() }, ByteArray(32) { (0x40 + id).toByte() })

    /** One or more records of every sealed category: identity, grace and current SPK, OTPKs, sessions, pending frames. */
    private suspend fun populate(storage: ClientStorage) {
        storage.identity.store(LocalIdentity(ByteArray(32) { 0x11 }, ByteArray(32) { 0x5A }))
        storage.preKeys.storeCurrentSignedPreKey(spk(1), Instant.fromEpochMilliseconds(1_000))
        storage.preKeys.storeCurrentSignedPreKey(spk(2), Instant.fromEpochMilliseconds(2_000)) // 1 enters its grace period
        storage.preKeys.storeOneTimePreKeys(listOf(otpk(10), otpk(11)))
        storage.sessions.store(SecureSession(BOB, "bob-session-state".encodeToByteArray()))
        storage.sessions.store(SecureSession(CAROL, "carol-session-state".encodeToByteArray()))
        storage.pendingOutbound.store(BOB, messageId(1), "pending-1".encodeToByteArray())
        storage.pendingOutbound.store(BOB, messageId(2), "pending-2".encodeToByteArray())
        storage.pendingOutbound.store(CAROL, messageId(1), "pending-3".encodeToByteArray())
        storage.processedInbound.markProcessed(ALICE, messageId(3))
        storage.remoteIdentities.store(BOB, ByteArray(32) { 0x77 })
    }

    /** The logical contents, as a comparable string. Opens every record. */
    private suspend fun contents(storage: ClientStorage): String = buildString {
        val identity = storage.identity.identity()
        append("identity=${identity?.publicKey?.toHex()}/${identity?.privateKey?.toHex()};")
        for (info in storage.preKeys.signedPreKeyInfos()) {
            val key = assertNotNull(storage.preKeys.signedPreKey(info.id))
            append("spk=$info/${key.publicKey.toHex()}/${key.signature.toHex()}/${key.privateKey.toHex()};")
        }
        append("currentSpk=${storage.preKeys.currentSignedPreKey()?.id};highest=${storage.preKeys.highestSignedPreKeyId()}/${storage.preKeys.highestOneTimePreKeyId()};")
        for (public in storage.preKeys.publicOneTimePreKeys()) {
            append("otpk=${public.id}/${storage.preKeys.oneTimePreKey(public.id)?.privateKey?.toHex()};")
        }
        for (remote in listOf(BOB, CAROL, DAVE)) {
            append("session=$remote/${storage.sessions.load(remote)?.state?.toHex()};")
            for (pending in storage.pendingOutbound.list(remote)) append("pending=$remote/${pending.id}/${pending.sequence}/${pending.frame.toHex()};")
            append("pin=$remote/${storage.remoteIdentities.identityKey(remote)?.toHex()};")
        }
        append("processed=${storage.processedInbound.isProcessed(ALICE, messageId(3))}")
    }

    /** Key IDs of every sealed value, per column, from the raw record headers. */
    private fun keyIdsByColumn(): Map<String, List<Int>> = SEALED_COLUMNS.associate { (table, column) ->
        "$table.$column" to driver.blobs("SELECT $column FROM $table WHERE $column IS NOT NULL ORDER BY rowid").map { SealedRecords.keyId(it).value }
    }

    /** Key IDs of every sealed record except the key checks. */
    private fun recordKeyIds(): List<Int> = keyIdsByColumn().filterKeys { !it.startsWith("storage_encryption.") }.values.flatten()

    /** Nonce of every sealed record except the key checks, keyed by table, column and rowid. */
    private fun nonces(): Map<String, String> = SEALED_COLUMNS.filter { it.first != "storage_encryption" }.flatMap { (table, column) ->
        val rowids = driver.longs("SELECT rowid FROM $table ORDER BY rowid")
        val values = driver.blobs("SELECT $column FROM $table ORDER BY rowid")
        rowids.zip(values) { rowid, value -> "$table.$column.$rowid" to value.copyOfRange(10, 22).toHex() }
    }.toMap()

    /** Every non-sealed column of every table except the storage key state. */
    private fun plainColumns(): Map<String, List<String?>> {
        val sealed = SEALED_COLUMNS.toSet()
        return driver.tables().filter { it != "storage_encryption" }.associateWith { table ->
            val names = driver.strings("SELECT name FROM pragma_table_info('$table')").filterNotNull().filter { (table to it) !in sealed }
            driver.strings("SELECT ${names.joinToString(" || '|' || ") { "quote(\"$it\")" }} FROM \"$table\" ORDER BY rowid")
        }
    }

    private fun state(column: String): Long? = driver.longs("SELECT $column FROM storage_encryption").single()

    /** Resumes until STABLE (bounded) and returns the number of resume calls. */
    private suspend fun SqlDelightClientStorage.finishRotation(maxRecords: Int = 3): Int {
        var steps = 0
        completeStorageKeyRotation {
            steps++
            resumeStorageKeyRotation(maxRecords)
        }
        return steps
    }

    private fun providerKey(id: StorageKeyId): StorageEncryptionKey = assertNotNull(keys.keys[namespace]?.get(id))

    @Test
    fun newDatabaseIsStableOnKey1() = runTest {
        val storage = open()
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K1, null, null, 0), storage.storageKeyRotationStatus())
        assertEquals(1L, state("highest_key_id"))
        assertEquals(0L, state("rotation_phase"))
    }

    @Test
    fun rotationMakesTheNewKeyCurrentWhileOldRecordsStayReadable() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        assertEquals(List(POPULATED_RECORDS.toInt()) { 1 }, recordKeyIds())

        assertEquals(K2, storage.rotateStorageKey())
        assertEquals(
            StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, POPULATED_RECORDS),
            storage.storageKeyRotationStatus(),
        )
        assertEquals(setOf(K1, K2), keys.ids(namespace))
        val ids = keyIdsByColumn()
        assertEquals(listOf(2), ids["storage_encryption.key_check"], "the key check proves the new current key")
        assertEquals(listOf(1), ids["storage_encryption.retiring_key_check"], "the old key check proves the retained key")
        assertEquals(List(POPULATED_RECORDS.toInt()) { 1 }, recordKeyIds(), "rotation re-encrypts nothing by itself")
        assertEquals(before, contents(storage))

        // New records are sealed with key 2 immediately; the old ones stay as they were.
        storage.sessions.store(SecureSession(DAVE, "dave".encodeToByteArray()))
        storage.sessions.store(SecureSession(BOB, "bob-updated".encodeToByteArray()))
        storage.pendingOutbound.store(DAVE, messageId(9), "new".encodeToByteArray())
        storage.preKeys.storeOneTimePreKeys(listOf(otpk(12)))
        storage.preKeys.storeCurrentSignedPreKey(spk(3), Instant.fromEpochMilliseconds(3_000))
        assertEquals(listOf(2), driver.blobs("SELECT sealed_state FROM session WHERE remote_user_id = 'dave'").map { SealedRecords.keyId(it).value })
        assertEquals(listOf(2), driver.blobs("SELECT sealed_state FROM session WHERE remote_user_id = 'bob'").map { SealedRecords.keyId(it).value })
        assertEquals(listOf(2), driver.blobs("SELECT sealed_frame FROM pending_outbound_message WHERE recipient_user_id = 'dave'").map { SealedRecords.keyId(it).value })
        assertEquals(listOf(2), driver.blobs("SELECT sealed_key_pair FROM one_time_pre_key WHERE id = 12").map { SealedRecords.keyId(it).value })
        assertEquals(listOf(2), driver.blobs("SELECT sealed_key_pair FROM signed_pre_key WHERE id = 3").map { SealedRecords.keyId(it).value })
        assertEquals(POPULATED_RECORDS - 1, storage.storageKeyRotationStatus().remainingRecords, "Bob's session was rewritten with key 2")
    }

    @Test
    fun fullMigrationRetiresTheOldKey() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        val plainBefore = plainColumns()
        val noncesBefore = nonces()

        storage.rotateStorageKey()
        val steps = storage.finishRotation(maxRecords = 3)
        assertTrue(steps >= 3, "10 records in batches of 3")

        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K2, null, null, 0), storage.storageKeyRotationStatus())
        val ids = keyIdsByColumn()
        assertEquals(List(POPULATED_RECORDS.toInt()) { 2 }, recordKeyIds())
        assertEquals(listOf(2), ids["storage_encryption.key_check"])
        assertEquals(emptyList(), ids["storage_encryption.retiring_key_check"])
        assertEquals(2L, state("highest_key_id"))
        assertNull(state("retiring_key_id"))
        assertEquals(setOf(K2), keys.ids(namespace), "key 1 was removed from the provider")

        // Only the encryption changed: same contents, same plaintext columns, fresh nonces.
        assertEquals(before, contents(storage))
        assertEquals(plainBefore, plainColumns())
        val noncesAfter = nonces()
        assertEquals(noncesBefore.keys, noncesAfter.keys, "rows were updated in place")
        for ((row, nonce) in noncesBefore) assertFalse(nonce == noncesAfter[row], "fresh nonce for $row")

        // Restart: key 2 alone opens it.
        assertEquals(before, contents(open()))
        assertEquals(before, contents(open(StaticStorageKeyProvider(providerKey(K2)))))
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { open(StaticStorageKeyProvider(TestKeys.A)) }
    }

    @Test
    fun partialMigrationResumesAfterRestart() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        storage.rotateStorageKey()

        val status = storage.resumeStorageKeyRotation(4)
        assertEquals(StorageKeyRotationPhase.MIGRATING, status.phase)
        assertEquals(POPULATED_RECORDS - 4, status.remainingRecords)
        assertEquals(mapOf(1 to 6, 2 to 4), recordKeyIds().groupingBy { it }.eachCount())

        // Restart in the middle: both keys are needed and both work.
        val restarted = open()
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.MIGRATING, K2, null, K1, 6), restarted.storageKeyRotationStatus())
        assertEquals(before, contents(restarted))

        // New writes after the restart still use key 2.
        restarted.pendingOutbound.store(DAVE, messageId(5), "after restart".encodeToByteArray())
        assertEquals(2, SealedRecords.keyId(driver.blob("SELECT sealed_frame FROM pending_outbound_message WHERE recipient_user_id = 'dave'")).value)
        val expected = contents(restarted)

        restarted.finishRotation()
        assertEquals(List(POPULATED_RECORDS.toInt() + 1) { 2 }, recordKeyIds())
        assertEquals(setOf(K2), keys.ids(namespace))
        assertEquals(expected, contents(open()))
    }

    @Test
    fun migrationOrderIsIdentityPreKeysSessionsPending() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        storage.resumeStorageKeyRotation(1)
        assertEquals(listOf(2), keyIdsByColumn()["local_identity.sealed_identity"])
        storage.resumeStorageKeyRotation(2)
        assertEquals(listOf(2, 2), keyIdsByColumn()["signed_pre_key.sealed_key_pair"])
        storage.resumeStorageKeyRotation(4)
        assertEquals(listOf(2, 2), keyIdsByColumn()["one_time_pre_key.sealed_key_pair"])
        assertEquals(listOf(2, 2), keyIdsByColumn()["session.sealed_state"])
        assertEquals(listOf(1, 1, 1), keyIdsByColumn()["pending_outbound_message.sealed_frame"])
    }

    @Test
    fun crashAfterProviderCreationLeavesAPreparedRotation() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        keys.crashAfterCreate = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.rotateStorageKey() }

        raw()
        assertEquals(1L, state("rotation_phase"))
        assertEquals(1L, state("key_id"))
        assertEquals(2L, state("next_key_id"))
        assertEquals(2L, state("highest_key_id"))
        assertEquals(setOf(K1, K2), keys.ids(namespace), "key 2 is persisted but not in use")
        assertEquals(List(POPULATED_RECORDS.toInt()) { 1 }, recordKeyIds())

        // The database still works on key 1 alone, and new records use key 1.
        val restarted = open(StaticStorageKeyProvider(providerKey(K1)))
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.PREPARING, K1, K2, null, 0), restarted.storageKeyRotationStatus())
        restarted.sessions.store(SecureSession(DAVE, "dave".encodeToByteArray()))
        assertEquals(1, SealedRecords.keyId(driver.blob("SELECT sealed_state FROM session WHERE remote_user_id = 'dave'")).value)
        val expected = contents(restarted)
        assertTrue(expected.startsWith(before.substringBefore("session=")))

        // Resuming uses the same key ID and the key the provider already has.
        keys.crashAfterCreate = false
        val orphan = providerKey(K2).copyBytes()
        val resumed = open()
        assertEquals(K2, resumed.rotateStorageKey())
        assertContentEquals(orphan, providerKey(K2).copyBytes())
        assertEquals(2L, state("highest_key_id"))
        assertEquals(StorageKeyRotationPhase.MIGRATING, resumed.storageKeyRotationStatus().phase)
        resumed.finishRotation()
        assertEquals(expected, contents(open()))
    }

    @Test
    fun providerFailureBeforeCreationIsResumable() = runTest {
        val storage = open()
        populate(storage)
        keys.failCreate = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.rotateStorageKey() }
        assertEquals(setOf(K1), keys.ids(namespace))
        assertEquals(StorageKeyRotationPhase.PREPARING, storage.storageKeyRotationStatus().phase)
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.resumeStorageKeyRotation() }

        keys.failCreate = false
        assertEquals(StorageKeyRotationPhase.MIGRATING, storage.resumeStorageKeyRotation().phase)
        assertEquals(K2, storage.storageKeyRotationStatus().currentKeyId)
    }

    @Test
    fun leftoverProviderKeyIsHarmless() = runTest {
        val storage = open()
        populate(storage)
        // A key 2 item from an earlier install that this database never used.
        val leftover = StorageEncryptionKey(K2, ByteArray(32) { 0x42 })
        keys.put(namespace, leftover)

        val before = contents(open())
        val restarted = open()
        assertEquals(K2, restarted.rotateStorageKey())
        assertContentEquals(leftover.copyBytes(), providerKey(K2).copyBytes(), "an existing provider key is never overwritten")
        restarted.finishRotation()
        assertEquals(before, contents(open()))
    }

    @Test
    fun migratingDatabaseNeedsBothKeys() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        storage.resumeStorageKeyRotation(4)
        val key1 = providerKey(K1)
        val key2 = providerKey(K2)
        val before = raw().dump()

        // Old key lost while records still use it: fail closed, never treat them as absent.
        repeat(2) { assertFailsWith<StorageEncryptionException.KeyUnavailable> { open(StaticStorageKeyProvider(key2)) } }
        // New key lost: fail closed, never roll back to key 1.
        repeat(2) { assertFailsWith<StorageEncryptionException.KeyUnavailable> { open(StaticStorageKeyProvider(key1)) } }
        // Wrong bytes for the old key.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            open(StaticStorageKeyProvider(key2, StorageEncryptionKey(K1, ByteArray(32) { 9 })))
        }
        assertEquals(before, raw().dump(), "failed opens change nothing")
        assertEquals(2L, state("rotation_phase"))
        assertEquals(2L, state("key_id"))

        open(StaticStorageKeyProvider(key2, key1)).finishRotation()
        assertEquals(List(POPULATED_RECORDS.toInt()) { 2 }, recordKeyIds())
    }

    @Test
    fun crashBeforeProviderRemovalIsRecoverable() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        storage.rotateStorageKey()
        keys.failRemove = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.finishRotation(100) }

        raw()
        assertEquals(3L, state("rotation_phase"))
        assertEquals(1L, state("retiring_key_id"))
        assertEquals(listOf(0L), driver.longs("SELECT retiring_key_check IS NOT NULL FROM storage_encryption"), "the old key check is gone")
        assertEquals(setOf(K1, K2), keys.ids(namespace), "nothing was removed yet")
        assertEquals(List(POPULATED_RECORDS.toInt()) { 2 }, recordKeyIds())

        // RETIRING needs only the current key.
        val key2Only = open(StaticStorageKeyProvider(providerKey(K2)))
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.RETIRING, K2, null, K1, 0), key2Only.storageKeyRotationStatus())
        assertEquals(before, contents(key2Only))

        keys.failRemove = false
        assertEquals(StorageKeyRotationPhase.STABLE, open().resumeStorageKeyRotation().phase)
        assertEquals(setOf(K2), keys.ids(namespace))
        assertEquals(before, contents(open()))
    }

    @Test
    fun crashAfterProviderRemovalIsRecoverable() = runTest {
        val storage = open()
        populate(storage)
        val before = contents(storage)
        storage.rotateStorageKey()
        keys.crashAfterRemove = true
        assertFailsWith<InjectedCrash> { storage.finishRotation(100) }

        raw()
        assertEquals(3L, state("rotation_phase"))
        assertEquals(setOf(K2), keys.ids(namespace), "key 1 is gone before the database recorded it")

        // Opening needs only key 2, and resuming accepts that key 1 is already gone.
        keys.crashAfterRemove = false
        val restarted = open()
        assertEquals(before, contents(restarted))
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, K2, null, null, 0), restarted.resumeStorageKeyRotation())
        assertEquals(0L, state("rotation_phase"))
    }

    @Test
    fun missingCurrentKeyAfterRetirementStartsFailsClosed() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        keys.failRemove = true
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.finishRotation(100) }

        keys.lose(namespace, K2)
        repeat(2) { assertFailsWith<StorageEncryptionException.KeyUnavailable> { open() } }
        assertEquals(3L, state("rotation_phase"))
        assertEquals(2L, state("key_id"))
    }

    @Test
    fun recordThatFailsToOpenStopsTheMigration() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        // Damage one one-time prekey record that is still sealed with key 1.
        driver.exec("UPDATE one_time_pre_key SET sealed_key_pair = ? WHERE id = 11", driver.blob("SELECT sealed_key_pair FROM one_time_pre_key WHERE id = 11").flipped(30))

        // The whole batch rolls back.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.resumeStorageKeyRotation(100) }
        assertEquals(List(POPULATED_RECORDS.toInt()) { 1 }, recordKeyIds())
        // Smaller batches commit up to the damaged record, then stop there.
        storage.resumeStorageKeyRotation(3) // identity, both signed prekeys
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.resumeStorageKeyRotation(3) }
        storage.resumeStorageKeyRotation(1) // one-time prekey 10
        repeat(2) { assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.resumeStorageKeyRotation(1) } }
        assertEquals(mapOf(1 to 6, 2 to 4), recordKeyIds().groupingBy { it }.eachCount())
        assertEquals(StorageKeyRotationPhase.MIGRATING, storage.storageKeyRotationStatus().phase)
        assertEquals(setOf(K1, K2), keys.ids(namespace), "the old key is kept")
    }

    @Test
    fun recordOfAnUnknownKeyStopsTheMigration() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        storage.finishRotation(100)
        storage.rotateStorageKey()
        // A session record sealed with a key this database never had.
        val foreign = ClientRecordCipher(StorageEncryptionKey(StorageKeyId(7), ByteArray(32) { 3 }))
        driver.exec("UPDATE session SET sealed_state = ? WHERE remote_user_id = 'carol'", foreign.sealSession(SecureSession(CAROL, byteArrayOf(1))))

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.finishRotation(100) }
        assertEquals(StorageKeyRotationPhase.MIGRATING, storage.storageKeyRotationStatus().phase)
        assertEquals(setOf(K2, K3), keys.ids(namespace))
    }

    @Test
    fun sealedValueTheBatchesDoNotSelectBlocksRetirement() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        // A key check is never re-encrypted, so only the scan sees one that names the retiring key.
        driver.exec("UPDATE storage_encryption SET key_check = retiring_key_check")

        assertFailsWith<IllegalStateException> { storage.resumeStorageKeyRotation(100) }
        assertEquals(List(POPULATED_RECORDS.toInt()) { 2 }, recordKeyIds(), "the batch committed")
        assertEquals(2L, state("rotation_phase"), "RETIRING was rolled back")
        assertEquals(listOf(1L), driver.longs("SELECT retiring_key_check IS NOT NULL FROM storage_encryption"))
        assertEquals(setOf(K1, K2), keys.ids(namespace), "the old key is kept")
    }

    @Test
    fun cancellationRollsBackOnlyTheRunningBatch() = runTest {
        val created = mutableListOf<FailingRecords>()
        val storage = open(records = created)
        populate(storage)
        storage.rotateStorageKey()
        assertEquals(POPULATED_RECORDS - 2, storage.resumeStorageKeyRotation(2).remainingRecords)

        val migrating = created.last()
        migrating.cancelAtSeal = migrating.seals + 3
        assertFailsWith<CancellationException> { storage.resumeStorageKeyRotation(5) }
        assertEquals(mapOf(1 to 8, 2 to 2), recordKeyIds().groupingBy { it }.eachCount(), "only the cancelled batch rolled back")
        assertEquals(StorageKeyRotationPhase.MIGRATING, storage.storageKeyRotationStatus().phase)

        migrating.cancelAtSeal = null
        storage.finishRotation()
        assertEquals(List(POPULATED_RECORDS.toInt()) { 2 }, recordKeyIds())
    }

    @Test
    fun rotateDuringARotationIsRefused() = runTest {
        val storage = open()
        populate(storage)
        storage.rotateStorageKey()
        val failure = assertFailsWith<StorageKeyRotationInProgressException> { storage.rotateStorageKey() }
        assertEquals(StorageKeyRotationPhase.MIGRATING, failure.status.phase)
        assertEquals(2L, state("highest_key_id"))
        assertEquals(setOf(K1, K2), keys.ids(namespace))
    }

    @Test
    fun keyIdsAreNeverReused() = runTest {
        val storage = open()
        populate(storage)
        assertEquals(K2, storage.rotateStorageKey())
        storage.finishRotation(100)
        assertEquals(K3, storage.rotateStorageKey())
        storage.finishRotation(100)
        assertEquals(setOf(K3), keys.ids(namespace))
        assertEquals(3L, state("highest_key_id"))
        assertEquals(List(POPULATED_RECORDS.toInt()) { 3 }, recordKeyIds())
    }

    @Test
    fun exhaustedKeyIdsFailExplicitly() = runTest {
        populate(open())
        raw().exec("UPDATE storage_encryption SET highest_key_id = 2147483647")
        val storage = open()
        assertFailsWith<StorageEncryptionException.KeyIdsExhausted> { storage.rotateStorageKey() }
        assertEquals(0L, state("rotation_phase"))
        assertEquals(setOf(K1), keys.ids(namespace))
    }

    @Test
    fun staleInstanceCannotWriteWithTheOldKey() = runTest {
        val first = open()
        populate(first)
        val second = SqlDelightClientStorage.open(database.open(), keys.provider(namespace))
        first.rotateStorageKey()

        assertFailsWith<StorageEncryptionException.KeyUnavailable> { second.sessions.store(SecureSession(DAVE, byteArrayOf(1))) }
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { second.resumeStorageKeyRotation() }
        assertNull(first.sessions.load(DAVE))
    }

    @Test
    fun rotationInsideATransactionIsRefused() = runTest {
        val storage = open()
        populate(storage)
        assertFailsWith<IllegalStateException> { storage.transaction { storage.rotateStorageKey() } }
        assertFailsWith<IllegalStateException> { storage.transaction { storage.resumeStorageKeyRotation() } }
        assertEquals(0L, state("rotation_phase"))
    }

    @Test
    fun inconsistentRotationStateFailsClosed() = runTest {
        populate(open())
        for (tamper in listOf(
            "UPDATE storage_encryption SET rotation_phase = 2",
            "UPDATE storage_encryption SET rotation_phase = 1",
            "UPDATE storage_encryption SET retiring_key_id = 1",
            "UPDATE storage_encryption SET highest_key_id = 0",
            // Invalid high-water mark together with an inconsistent phase; a value above Int.MAX_VALUE.
            "UPDATE storage_encryption SET highest_key_id = 0, rotation_phase = 2",
            "UPDATE storage_encryption SET highest_key_id = 2147483648",
        )) {
            val driver = raw()
            val before = driver.dump()
            driver.exec(tamper)
            assertFailsWith<StorageEncryptionException.MalformedRecord>(tamper) { open() }
            raw().exec("DELETE FROM storage_encryption")
            restore(before.getValue("storage_encryption").single())
        }
        assertEquals(StorageKeyRotationPhase.STABLE, open().storageKeyRotationStatus().phase)
        raw().exec("UPDATE storage_encryption SET rotation_phase = 9")
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> { open() }
    }

    /** Restores the storage_encryption row from its [dump] form. */
    private fun restore(row: String?) {
        driver.exec("INSERT INTO storage_encryption VALUES (${row!!.replace("|", ", ")})")
    }

    @Test
    fun sealedColumnsCoverEverySealedValueInTheSchema() = runTest {
        open()
        val plaintextBlobs = setOf(
            "remote_identity" to "identity_key",
            "retired_session_initiation" to "initiation_id",
            "pending_outbound_message" to "message_id",
            "processed_inbound_message" to "message_id",
        )
        val blobColumns = driver.tables().flatMap { table ->
            driver.strings("SELECT name FROM pragma_table_info('$table') WHERE type = 'BLOB'").map { table to it!! }
        }.toSet()
        assertEquals(blobColumns, SEALED_COLUMNS.toSet() + plaintextBlobs, "a new BLOB column must be scanned or listed as plaintext")
        assertTrue(SEALED_COLUMNS.none { it in plaintextBlobs })
        // Every sealed_* column is scanned, whatever its declared type.
        val sealedNamed = driver.tables().flatMap { table ->
            driver.strings("SELECT name FROM pragma_table_info('$table') WHERE name LIKE 'sealed%' OR name LIKE '%key_check'").map { table to it!! }
        }.toSet()
        assertTrue(SEALED_COLUMNS.toSet().containsAll(sealedNamed))
    }
}
