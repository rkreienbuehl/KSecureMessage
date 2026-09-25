package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.SealedRecords
import dev.kreienbuehl.ksecuremessage.storage.encryption.ClientRecordCipher
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationPhase
import dev.kreienbuehl.ksecuremessage.storage.rotation.StorageKeyRotationStatus
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))
private val DAVE = DeviceAddress(UserId("dave"), DeviceId("desktop"))

private val PENDING_TEXT = "super-secret-pending-message"

/** Milestone 8 plaintext databases encrypted by SqlDelightClientStorage.open. */
class SqlDelightMigrationTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val clock = TestClock(Instant.fromEpochMilliseconds(1_000_000_000_000))
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3, signedPreKeyGracePeriod = 30.days)
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() = database.close()

    private fun client(address: DeviceAddress, storage: ClientStorage) = SecureMessageClient(address, storage, engine, network, config, clock)

    /** Opens the database file like an application restart, with the current schema. */
    private suspend fun reopen(records: MutableList<FailingRecords>? = null, keys: StorageKeyProvider = TestKeys.providerA): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return if (records == null) SqlDelightClientStorage.open(driver, keys) else SqlDelightClientStorage.open(driver, keys, FailingRecords.factory(records))
    }

    /** What Bob had before the upgrade, to compare with afterwards. */
    private class M8State(
        val identityPublic: ByteArray,
        val identityPrivate: ByteArray,
        val signedPrivate: Map<Int, ByteArray>,
        val oneTimePrivate: Map<Int, ByteArray>,
        val sessionState: ByteArray,
        val pendingId: LogicalMessageId,
        val pendingSequence: Long,
        val pendingFrame: ByteArray,
        val processedId: LogicalMessageId,
        val retired: SessionInitiationId,
        val oldBundle: PreKeyBundle,
    )

    /**
     * Runs Alice and Bob on in-memory storage, then writes Bob's state into a
     * milestone 8 (schema version 5) database file exactly as the milestone 8
     * adapter stored it: plaintext key pairs, session state and pending frame.
     */
    private suspend fun m8Database(alice: SecureMessageClient): M8State {
        val bobStorage = InMemoryClientStorage()
        val bob = client(BOB, bobStorage)
        bob.initialize()
        network.publish(bob)
        // Fetched early by Carol: names signed prekey 0 and the last one-time prekey (Alice gets the first).
        val oldBundle = bob.currentPreKeyBundle().copy(oneTimePreKey = bob.publicOneTimePreKeys().last())
        clock.now += 1.days
        bob.rotateSignedPreKey() // signed prekey 0 enters its grace period
        network.publish(bob)

        val fromAlice = alice.send(BOB, "hi Bob".encodeToByteArray())
        network.receive(BOB).forEach { bob.decrypt(it) }
        network.receive(ALICE).forEach { alice.decrypt(it) }
        bob.send(ALICE, "hi Alice".encodeToByteArray())
        network.receive(ALICE).forEach { alice.decrypt(it) }
        network.receive(BOB).forEach { bob.decrypt(it) }
        val pending = bob.send(ALICE, PENDING_TEXT.encodeToByteArray())
        network.receive(ALICE) // lost in transit: stays pending at Bob

        val old = database.open(Version5Schema)
        val identity = assertNotNull(bobStorage.identity.identity())
        old.exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, ?, ?)", identity.publicKey, identity.privateKey)
        for (info in bobStorage.preKeys.signedPreKeyInfos()) {
            val key = assertNotNull(bobStorage.preKeys.signedPreKey(info.id))
            old.execute(
                null,
                "INSERT INTO signed_pre_key (id, public_key, signature, private_key, created_at, replaced_at) VALUES (?, ?, ?, ?, ?, ?)",
                6,
            ) {
                bindLong(0, info.id.value.toLong())
                bindBytes(1, key.publicKey)
                bindBytes(2, key.signature)
                bindBytes(3, key.privateKey)
                bindLong(4, info.createdAt?.toEpochMilliseconds())
                bindLong(5, info.replacedAt?.toEpochMilliseconds())
            }
        }
        val oneTime = bobStorage.preKeys.publicOneTimePreKeys().map { assertNotNull(bobStorage.preKeys.oneTimePreKey(it.id)) }
        for (key in oneTime) {
            old.execute(null, "INSERT INTO one_time_pre_key (id, public_key, private_key) VALUES (?, ?, ?)", 3) {
                bindLong(0, key.id.value.toLong())
                bindBytes(1, key.publicKey)
                bindBytes(2, key.privateKey)
            }
        }
        val current = assertNotNull(bobStorage.preKeys.currentSignedPreKey()).id.value
        old.exec(
            "UPDATE pre_key_state SET current_signed_pre_key_id = $current, highest_signed_pre_key_id = ${bobStorage.preKeys.highestSignedPreKeyId()?.value}, " +
                "highest_one_time_pre_key_id = ${bobStorage.preKeys.highestOneTimePreKeyId()?.value}",
        )
        val session = assertNotNull(bobStorage.sessions.load(ALICE))
        old.exec("INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', ?)", session.state)
        old.exec("INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('alice', 'phone', ?)", assertNotNull(bobStorage.remoteIdentities.identityKey(ALICE)))
        val retired = SessionInitiationId(ByteArray(32) { 7 })
        old.exec("INSERT INTO retired_session_initiation (remote_user_id, remote_device_id, initiation_id, signed_pre_key_id) VALUES ('dave', 'desktop', ?, 0)", retired.bytes)
        val stored = bobStorage.pendingOutbound.list(ALICE).single()
        // Sequence 5 with a high-water mark of 9: earlier messages were acknowledged and removed.
        old.exec("INSERT INTO pending_outbound_message (sequence, recipient_user_id, recipient_device_id, message_id, frame) VALUES (5, 'alice', 'phone', ?, ?)", pending.id.toByteArray(), stored.frame)
        old.exec("UPDATE sqlite_sequence SET seq = 9 WHERE name = 'pending_outbound_message'")
        old.exec("INSERT INTO processed_inbound_message (sender_user_id, sender_device_id, message_id) VALUES ('alice', 'phone', ?)", fromAlice.id.toByteArray())
        database.closeOpenDrivers()

        return M8State(
            identityPublic = identity.publicKey,
            identityPrivate = identity.privateKey,
            signedPrivate = bobStorage.preKeys.signedPreKeyInfos().associate { it.id.value to assertNotNull(bobStorage.preKeys.signedPreKey(it.id)).privateKey },
            oneTimePrivate = oneTime.associate { it.id.value to it.privateKey },
            sessionState = session.state,
            pendingId = pending.id,
            pendingSequence = 5,
            pendingFrame = stored.frame,
            processedId = fromAlice.id,
            retired = retired,
            oldBundle = oldBundle,
        )
    }

    private suspend fun aliceClient(): SecureMessageClient {
        val alice = client(ALICE, InMemoryClientStorage())
        alice.initialize()
        network.publish(alice)
        return alice
    }

    private fun sensitiveValues(): List<ByteArray> =
        driver.blobs("SELECT sealed_identity FROM local_identity") +
            driver.blobs("SELECT sealed_key_pair FROM signed_pre_key") +
            driver.blobs("SELECT sealed_key_pair FROM one_time_pre_key") +
            driver.blobs("SELECT sealed_state FROM session") +
            driver.blobs("SELECT sealed_frame FROM pending_outbound_message")

    @Test
    fun m8DatabaseIsEncryptedWithoutLosingState() = runTest {
        val alice = aliceClient()
        val m8 = m8Database(alice)
        val storage = reopen()

        // Logical state is unchanged.
        val identity = assertNotNull(storage.identity.identity())
        assertContentEquals(m8.identityPublic, identity.publicKey)
        assertContentEquals(m8.identityPrivate, identity.privateKey)
        assertEquals(listOf(0, 1), storage.preKeys.signedPreKeyInfos().map { it.id.value })
        val infos = storage.preKeys.signedPreKeyInfos()
        assertEquals(clock.now - 1.days, infos[0].createdAt)
        assertEquals(clock.now, infos[0].replacedAt)
        assertEquals(clock.now, infos[1].createdAt)
        assertTrue(infos[1].isCurrent)
        for ((id, private) in m8.signedPrivate) assertContentEquals(private, storage.preKeys.signedPreKey(SignedPreKeyId(id))?.privateKey)
        assertEquals(m8.oneTimePrivate.keys.toList(), storage.preKeys.publicOneTimePreKeys().map { it.id.value })
        for ((id, private) in m8.oneTimePrivate) {
            assertContentEquals(private, storage.preKeys.oneTimePreKey(OneTimePreKeyId(id))?.privateKey)
        }
        assertEquals(SignedPreKeyId(1), storage.preKeys.highestSignedPreKeyId())
        assertEquals(2, storage.preKeys.highestOneTimePreKeyId()?.value) // 0 was consumed by Alice
        assertContentEquals(m8.sessionState, storage.sessions.load(ALICE)?.state)
        assertNotNull(storage.remoteIdentities.identityKey(ALICE))
        assertTrue(storage.sessionInitiations.isRetired(DAVE, m8.retired))
        assertEquals(setOf(SignedPreKeyId(0)), storage.sessionInitiations.retiredSignedPreKeyIds())
        val pending = storage.pendingOutbound.list(ALICE).single()
        assertEquals(m8.pendingId, pending.id)
        assertEquals(m8.pendingSequence, pending.sequence)
        assertContentEquals(m8.pendingFrame, pending.frame)
        assertTrue(storage.processedInbound.isProcessed(ALICE, m8.processedId))

        // Active sensitive columns hold only encrypted records.
        assertEquals(listOf(1L), driver.longs("SELECT format FROM storage_encryption"))
        val secrets = listOf(m8.identityPrivate, m8.sessionState.copyOfRange(0, 32), PENDING_TEXT.encodeToByteArray()) +
            m8.signedPrivate.values + m8.oneTimePrivate.values
        for (value in sensitiveValues()) {
            assertTrue(value.isSealed())
            for (secret in secrets) assertFalse(value.toHex().contains(secret.toHex()))
        }
        assertTrue(driver.strings("SELECT name FROM sqlite_master WHERE name LIKE '%_m9'").isEmpty())

        // The AUTOINCREMENT high-water mark survived: sequence numbers are not reused.
        assertTrue(storage.pendingOutbound.store(CAROL, LogicalMessageId.random(), byteArrayOf(1)) > 9)
    }

    @Test
    fun conversationContinuesAfterMigration() = runTest {
        val alice = aliceClient()
        val m8 = m8Database(alice)
        suspend fun bob() = client(BOB, reopen())
        bob().initialize() // nothing to rotate or delete yet

        // The existing ratchet session continues: no new X3DH.
        alice.send(BOB, "after upgrade".encodeToByteArray())
        val envelope = network.receive(BOB).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(envelope.payload))
        assertEquals("after upgrade", assertIs<ReceiveResult.Message>(bob().decrypt(envelope)).plaintext.decodeToString())
        network.receive(ALICE).forEach { alice.decrypt(it) } // acknowledgement

        // The pending M8 message is resent with the same logical ID and fresh ciphertext, and acknowledged.
        assertEquals(listOf(m8.pendingId), bob().pendingMessages(ALICE).map { it.id })
        assertEquals(listOf(m8.pendingId), bob().retryPendingMessages(ALICE))
        val resent = assertIs<ReceiveResult.Message>(alice.decrypt(network.receive(ALICE).single()))
        assertEquals(m8.pendingId, resent.id)
        assertEquals(PENDING_TEXT, resent.plaintext.decodeToString())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob().decrypt(network.receive(BOB).single())).cleared)
        assertEquals(emptyList(), bob().pendingMessages(ALICE))

        // A delayed first contact that names the replaced signed prekey is accepted during its grace period.
        val carol = client(CAROL, InMemoryClientStorage())
        carol.initialize()
        network.bundles[BOB] = m8.oldBundle
        carol.send(BOB, "delayed".encodeToByteArray())
        val initiation = network.receive(BOB).single()
        assertEquals(SignedPreKeyId(0), assertIs<PreKeyMessage>(CiphertextMessageCodec.decode(initiation.payload)).signedPreKeyId)
        assertEquals("delayed", assertIs<ReceiveResult.Message>(bob().decrypt(initiation)).plaintext.decodeToString())

        // After the grace period the replaced key is deleted, its retired initiations pruned, IDs kept.
        clock.now += 30.days
        bob().initialize()
        val storage = reopen()
        assertEquals(null, storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertEquals(emptySet(), storage.sessionInitiations.retiredSignedPreKeyIds())
        assertTrue(assertNotNull(storage.preKeys.highestSignedPreKeyId()).value >= 1)
    }

    @Test
    fun failedMigrationRollsBackCompletely() = runTest {
        m8Database(aliceClient())
        driver = database.open()
        val before = driver.dump()
        val schema = driver.strings("SELECT sql FROM sqlite_master ORDER BY name")

        // One identity, two signed prekeys, two one-time prekeys (0 was consumed), one session, one pending message.
        val seals = 1 + 2 + 2 + 1 + 1
        assertEquals(listOf(2L), driver.longs("SELECT count(*) FROM one_time_pre_key"))
        for (failAt in 1..seals) {
            database.closeOpenDrivers()
            driver = database.open()
            val records = mutableListOf<FailingRecords>()
            assertFailsWith<IllegalStateException>("seal $failAt") {
                SqlDelightClientStorage.open(driver, TestKeys.providerA, FailingRecords.factory(records, failAtSeal = failAt))
            }
            assertEquals(failAt, records.single().seals)
            assertEquals(before, driver.dump(), "seal $failAt: rows unchanged, marker still 0")
            assertEquals(schema, driver.strings("SELECT sql FROM sqlite_master ORDER BY name"), "seal $failAt: no rebuilt tables")
        }

        // The untouched database migrates on the next open.
        val records = mutableListOf<FailingRecords>()
        database.closeOpenDrivers()
        driver = database.open()
        val storage = SqlDelightClientStorage.open(driver, TestKeys.providerA, FailingRecords.factory(records))
        assertEquals(seals, records.single().seals)
        assertEquals(listOf(1L), driver.longs("SELECT format FROM storage_encryption"))
        assertNotNull(storage.identity.identity())
    }

    @Test
    fun legacyDatabaseWithoutKeyIsLeftUnchanged() = runTest {
        m8Database(aliceClient())
        driver = database.open()
        val before = driver.dump()
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { reopen(keys = TestKeys.missing) }
        assertEquals(before, driver.dump())
        assertEquals(listOf(0L), driver.longs("SELECT format FROM storage_encryption"))
        assertNotNull(reopen().identity.identity())
    }

    @Test
    fun migratedSchemaEqualsNewSchema() = runTest {
        m8Database(aliceClient())
        reopen()
        val migrated = driver.tables().associateWith { driver.columns(it) }
        val migratedIndexes = driver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1")

        val fresh = TestDatabase()
        try {
            val freshDriver = fresh.open()
            SqlDelightClientStorage.open(freshDriver, TestKeys.providerA)
            assertEquals(freshDriver.tables().associateWith { freshDriver.columns(it) }, migrated)
            assertEquals(freshDriver.strings("SELECT tbl_name || ':' || name FROM sqlite_master WHERE type = 'index' ORDER BY 1"), migratedIndexes)
            assertEquals(freshDriver.longs("PRAGMA user_version"), driver.longs("PRAGMA user_version"))
        } finally {
            fresh.close()
        }
    }

    @Test
    fun migrationWorksWithForeignKeysEnforced() = runTest {
        m8Database(aliceClient())
        driver = database.openWithForeignKeys()
        assertEquals(listOf(1L), driver.longs("PRAGMA foreign_keys"))
        val storage = SqlDelightClientStorage.open(driver, TestKeys.providerA)
        assertEquals(SignedPreKeyId(1), storage.preKeys.currentSignedPreKey()?.id)
        assertTrue(driver.strings("SELECT \"table\" FROM pragma_foreign_key_check").isEmpty())
    }

    @Test
    fun olderSchemasMigrateThroughEncryption() = runTest {
        // A milestone 3 (schema version 1) database goes through every .sqm and then record encryption.
        val old = database.open(Version1Schema)
        old.exec("INSERT INTO local_identity (id, public_key, private_key) VALUES (0, X'0102', X'0304')")
        old.exec("INSERT INTO session (remote_user_id, remote_device_id, state) VALUES ('alice', 'phone', X'0506')")
        val storage = reopen()
        assertContentEquals(byteArrayOf(3, 4), storage.identity.identity()?.privateKey)
        assertContentEquals(byteArrayOf(5, 6), storage.sessions.load(ALICE)?.state)
        assertTrue(sensitiveValues().all { it.isSealed() })
        // Opening again does not migrate again.
        val sealed = driver.blob("SELECT sealed_identity FROM local_identity")
        reopen()
        assertContentEquals(sealed, driver.blob("SELECT sealed_identity FROM local_identity"))
    }

    @Test
    fun milestone10DatabaseIsStableOnItsKeyWithoutReEncryption() = runTest {
        // A schema version 6 database as milestones 9 and 10 wrote it, sealed with key 1.
        val records = ClientRecordCipher(TestKeys.A)
        val old = database.open(Version6Schema)
        old.exec("INSERT INTO local_identity (id, sealed_identity) VALUES (0, ?)", records.sealIdentity(LocalIdentity(ByteArray(32) { 1 }, ByteArray(32) { 2 })))
        val spk = SignedPreKeyPair(SignedPreKeyId(4), ByteArray(32) { 3 }, ByteArray(64) { 4 }, ByteArray(32) { 5 })
        old.exec("INSERT INTO signed_pre_key (id, sealed_key_pair, created_at, replaced_at) VALUES (4, ?, 1000, NULL)", records.sealSignedPreKey(spk))
        old.exec("UPDATE pre_key_state SET current_signed_pre_key_id = 4, highest_signed_pre_key_id = 4, highest_one_time_pre_key_id = 8")
        old.exec("INSERT INTO one_time_pre_key (id, sealed_key_pair) VALUES (8, ?)", records.sealOneTimePreKey(OneTimePreKeyPair(OneTimePreKeyId(8), ByteArray(32) { 6 }, ByteArray(32) { 7 })))
        old.exec("INSERT INTO session (remote_user_id, remote_device_id, sealed_state) VALUES ('alice', 'phone', ?)", records.sealSession(SecureSession(ALICE, byteArrayOf(9, 9))))
        old.exec("INSERT INTO remote_identity (remote_user_id, remote_device_id, identity_key) VALUES ('alice', 'phone', ?)", ByteArray(32) { 8 })
        old.exec("INSERT INTO retired_session_initiation (remote_user_id, remote_device_id, initiation_id, signed_pre_key_id) VALUES ('dave', 'desktop', ?, 4)", ByteArray(32) { 7 })
        val pendingId = LogicalMessageId.random()
        old.exec(
            "INSERT INTO pending_outbound_message (recipient_user_id, recipient_device_id, message_id, sealed_frame) VALUES ('alice', 'phone', ?, ?)",
            pendingId.toByteArray(),
            records.sealPendingFrame(ALICE, pendingId, PENDING_TEXT.encodeToByteArray()),
        )
        old.exec("INSERT INTO processed_inbound_message (sender_user_id, sender_device_id, message_id) VALUES ('alice', 'phone', ?)", ByteArray(16) { 1 })
        old.exec("UPDATE storage_encryption SET key_id = 1, key_check = ?", records.sealKeyCheck())
        val before = old.dump()
        database.closeOpenDrivers()

        val storage = reopen()
        assertEquals(StorageKeyRotationStatus(StorageKeyRotationPhase.STABLE, StorageKeyId(1), null, null, 0), storage.storageKeyRotationStatus())
        assertEquals(listOf(8L), driver.longs("PRAGMA user_version"))
        // Every row is unchanged; storage_encryption only gained the rotation columns, and the
        // device authentication tables of schema version 8 mark the identity as awaiting its key.
        val after = driver.dump()
        val authTables = setOf("device_authentication_key", "device_authentication_state")
        assertEquals(before - "storage_encryption", after - "storage_encryption" - authTables)
        assertEquals(emptyList(), after.getValue("device_authentication_key"))
        assertEquals(listOf("0|1"), after.getValue("device_authentication_state"))
        assertEquals(before.getValue("storage_encryption").single() + "|1|0|NULL|NULL|NULL", after.getValue("storage_encryption").single())

        assertContentEquals(ByteArray(32) { 2 }, storage.identity.identity()?.privateKey)
        assertEquals(listOf(SignedPreKeyInfo(SignedPreKeyId(4), true, Instant.fromEpochMilliseconds(1000), null)), storage.preKeys.signedPreKeyInfos())
        assertContentEquals(ByteArray(32) { 7 }, storage.preKeys.oneTimePreKey(OneTimePreKeyId(8))?.privateKey)
        assertContentEquals(byteArrayOf(9, 9), storage.sessions.load(ALICE)?.state)
        assertContentEquals(ByteArray(32) { 8 }, storage.remoteIdentities.identityKey(ALICE))
        assertTrue(storage.sessionInitiations.isRetired(DAVE, SessionInitiationId(ByteArray(32) { 7 })))
        assertEquals(PENDING_TEXT, storage.pendingOutbound.get(ALICE, pendingId)?.frame?.decodeToString())
        assertTrue(storage.processedInbound.isProcessed(ALICE, LogicalMessageId.fromByteArray(ByteArray(16) { 1 })))
    }

    @Test
    fun milestone8DatabaseRotatesItsStorageKeyAndMessagingContinues() = runTest {
        val keys = MemoryKeyStore()
        val provider = { keys.provider("m8") }
        val alice = aliceClient()
        val m8 = m8Database(alice)
        // Milestone 9: the first open encrypts with provider key 1.
        val encrypted = reopen(keys = provider())
        assertEquals(setOf(StorageKeyId(1)), keys.ids("m8"))
        val spkInfos = encrypted.preKeys.signedPreKeyInfos()
        suspend fun bob() = client(BOB, reopen(keys = provider()))

        // Milestone 11: rotate, migrate a part, restart.
        assertEquals(StorageKeyId(2), encrypted.rotateStorageKey())
        assertEquals(StorageKeyRotationPhase.MIGRATING, encrypted.resumeStorageKeyRotation(2).phase)
        val mixed = sensitiveValues().map { SealedRecords.keyId(it).value }.groupingBy { it }.eachCount()
        assertEquals(mapOf(1 to 5, 2 to 2), mixed)

        // Messaging during the migration: the existing ratchet session continues, no new X3DH.
        alice.send(BOB, "during rotation".encodeToByteArray())
        val envelope = network.receive(BOB).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(envelope.payload))
        assertEquals("during rotation", assertIs<ReceiveResult.Message>(bob().decrypt(envelope)).plaintext.decodeToString())
        network.receive(ALICE).forEach { alice.decrypt(it) } // acknowledgement

        // Restart, resume to the end, retire key 1.
        val restarted = reopen(keys = provider())
        assertEquals(StorageKeyRotationPhase.MIGRATING, restarted.storageKeyRotationStatus().phase)
        completeStorageKeyRotation { restarted.resumeStorageKeyRotation(2) }
        assertEquals(setOf(StorageKeyId(2)), keys.ids("m8"))
        assertTrue(sensitiveValues().all { SealedRecords.keyId(it) == StorageKeyId(2) })

        // Signed prekey lifecycle metadata is untouched by the storage key rotation.
        assertEquals(spkInfos, reopen(keys = provider()).preKeys.signedPreKeyInfos())

        // The pending M8 message keeps its logical ID, sequence and frame, is resent and acknowledged.
        val pending = reopen(keys = provider()).pendingOutbound.list(ALICE).single()
        assertEquals(m8.pendingId, pending.id)
        assertEquals(m8.pendingSequence, pending.sequence)
        assertContentEquals(m8.pendingFrame, pending.frame)
        assertEquals(listOf(m8.pendingId), bob().retryPendingMessages(ALICE))
        val resent = network.receive(ALICE).single()
        assertIs<RatchetMessage>(CiphertextMessageCodec.decode(resent.payload))
        assertEquals(PENDING_TEXT, assertIs<ReceiveResult.Message>(alice.decrypt(resent)).plaintext.decodeToString())
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(bob().decrypt(network.receive(BOB).single())).cleared)
        assertEquals(emptyList(), bob().pendingMessages(ALICE))

        // Both directions keep working on the migrated storage.
        bob().send(ALICE, "after rotation".encodeToByteArray())
        assertEquals("after rotation", assertIs<ReceiveResult.Message>(alice.decrypt(network.receive(ALICE).single())).plaintext.decodeToString())
    }
}
