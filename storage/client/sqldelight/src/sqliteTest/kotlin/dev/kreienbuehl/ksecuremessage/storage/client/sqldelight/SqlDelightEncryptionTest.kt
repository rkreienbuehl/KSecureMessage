package dev.kreienbuehl.ksecuremessage.storage.client.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.encryption.StaticStorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.messageId
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
import kotlin.time.Instant

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))

private val SECRET_MESSAGE = "super-secret-pending-message".encodeToByteArray()
private val IDENTITY_SECRET = ByteArray(32) { 0x5A }
private val AUTH_SECRET = ByteArray(32) { 0x5B }
private val RECEIVED_SECRET = "super-secret-received-message".encodeToByteArray()
private val DIGEST = ByteArray(32) { 0x3C }
private val SESSION_MARKER = "session-state-marker-0123456789".encodeToByteArray()

/** Record encryption of SQLDelight storage, checked on the persisted bytes. */
class SqlDelightEncryptionTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = TestRelay()
    private val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
    private lateinit var driver: SqlDriver

    @AfterTest
    fun close() = database.close()

    /** Closes the open connection and opens the same file again, like an application restart. */
    private suspend fun reopen(
        keyProvider: StorageKeyProvider = TestKeys.providerA,
        records: MutableList<FailingRecords>? = null,
    ): SqlDelightClientStorage {
        database.closeOpenDrivers()
        driver = database.open()
        return if (records == null) {
            SqlDelightClientStorage.open(driver, keyProvider)
        } else {
            SqlDelightClientStorage.open(driver, keyProvider, FailingRecords.factory(records))
        }
    }

    private fun spk(id: Int) =
        SignedPreKeyPair(SignedPreKeyId(id), ByteArray(32) { (id + 1).toByte() }, ByteArray(64) { 0x33 }, ByteArray(32) { (0x60 + id).toByte() })

    private fun otpk(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), ByteArray(32) { (id + 2).toByte() }, ByteArray(32) { (0x40 + id).toByte() })

    /** Every sensitive column value, raw. */
    private fun sealedValues(): List<ByteArray> =
        driver.blobs("SELECT sealed_identity FROM local_identity") +
            driver.blobs("SELECT sealed_key_pair FROM device_authentication_key") +
            driver.blobs("SELECT sealed_key_pair FROM signed_pre_key") +
            driver.blobs("SELECT sealed_key_pair FROM one_time_pre_key") +
            driver.blobs("SELECT sealed_state FROM session") +
            driver.blobs("SELECT sealed_frame FROM pending_outbound_message")

    private fun assertNoPlaintext(vararg secrets: ByteArray) {
        val values = sealedValues()
        assertTrue(values.isNotEmpty())
        for (value in values) {
            assertTrue(value.isSealed(), "every sensitive value is an encrypted record")
            for (secret in secrets) assertFalse(value.toHex().contains(secret.toHex()), "plaintext in a sensitive column")
        }
    }

    private suspend fun populate(storage: ClientStorage) {
        storage.identity.store(LocalIdentity(ByteArray(32) { 0x11 }, IDENTITY_SECRET))
        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(ByteArray(32) { 0x12 }, AUTH_SECRET))
        storage.preKeys.storeCurrentSignedPreKey(spk(1), Instant.fromEpochMilliseconds(1_000))
        storage.preKeys.storeCurrentSignedPreKey(spk(2), Instant.fromEpochMilliseconds(2_000))
        storage.preKeys.storeOneTimePreKeys(listOf(otpk(10), otpk(11)))
        storage.sessions.store(SecureSession(BOB, SESSION_MARKER))
        storage.sessions.store(SecureSession(CAROL, SESSION_MARKER))
        storage.pendingOutbound.store(BOB, messageId(1), SECRET_MESSAGE)
        storage.pendingOutbound.store(BOB, messageId(2), SECRET_MESSAGE)
        storage.pendingOutbound.store(CAROL, messageId(1), SECRET_MESSAGE)
        storage.processedInbound.markCommitted(ALICE, messageId(3), DIGEST, Instant.fromEpochMilliseconds(3_000))
        storage.pendingInbound.store(ALICE, messageId(4), RECEIVED_SECRET, Instant.fromEpochMilliseconds(4_000))
    }

    @Test
    fun newDatabaseStoresOnlyEncryptedRecords() = runTest {
        populate(reopen())

        assertNoPlaintext(IDENTITY_SECRET, AUTH_SECRET, SESSION_MARKER, SECRET_MESSAGE, RECEIVED_SECRET, DIGEST, spk(1).privateKey, otpk(10).privateKey)
        assertTrue(driver.blob("SELECT sealed_key_pair FROM device_authentication_key").isSealed())
        assertTrue(driver.blob("SELECT sealed_frame FROM pending_inbound_message").isSealed())
        assertTrue(driver.blob("SELECT sealed_digest FROM processed_inbound_message").isSealed())
        assertEquals(listOf(1L), driver.longs("SELECT format FROM storage_encryption"))
        assertEquals(listOf(1L), driver.longs("SELECT key_id FROM storage_encryption"))
        assertTrue(driver.blob("SELECT key_check FROM storage_encryption").isSealed())

        // Everything survives a restart.
        val after = reopen()
        assertContentEquals(IDENTITY_SECRET, after.identity.identity()?.privateKey)
        assertContentEquals(AUTH_SECRET, after.deviceAuthentication.keyPair()?.privateKey)
        assertContentEquals(spk(1).privateKey, after.preKeys.signedPreKey(SignedPreKeyId(1))?.privateKey)
        assertContentEquals(spk(2).signature, after.preKeys.currentSignedPreKey()?.signature)
        assertContentEquals(otpk(11).privateKey, after.preKeys.oneTimePreKey(OneTimePreKeyId(11))?.privateKey)
        assertEquals(listOf(10, 11), after.preKeys.publicOneTimePreKeys().map { it.id.value })
        assertContentEquals(SESSION_MARKER, after.sessions.load(CAROL)?.state)
        assertEquals(listOf(messageId(1), messageId(2)), after.pendingOutbound.page(0, Int.MAX_VALUE, BOB).map { it.id })
        assertContentEquals(SECRET_MESSAGE, after.pendingOutbound.get(CAROL, messageId(1))?.frame)
        assertTrue(after.processedInbound.isProcessed(ALICE, messageId(3)))
        assertContentEquals(DIGEST, after.processedInbound.get(ALICE, messageId(3))?.digest)
        assertContentEquals(RECEIVED_SECRET, after.pendingInbound.get(ALICE, messageId(4))?.frame)
    }

    @Test
    fun sameValueEncryptsDifferentlyAndIsNeverEncryptedTwice() = runTest {
        val storage = reopen()
        storage.sessions.store(SecureSession(BOB, SESSION_MARKER))
        val first = driver.blob("SELECT sealed_state FROM session")
        storage.sessions.store(SecureSession(BOB, SESSION_MARKER))
        val second = driver.blob("SELECT sealed_state FROM session")
        assertFalse(first.contentEquals(second), "random nonces: the same state seals differently")

        // Load and store again, repeatedly: the stored record never becomes a record of a record.
        repeat(3) {
            val restarted = reopen()
            restarted.sessions.store(assertNotNull(restarted.sessions.load(BOB)))
        }
        assertContentEquals(SESSION_MARKER, reopen().sessions.load(BOB)?.state)
        assertEquals(second.size, driver.blob("SELECT sealed_state FROM session").size)
    }

    @Test
    fun wrongOrMissingKeyFailsClosed() = runTest {
        val alice = SecureMessageClient(ALICE, reopen(), engine, network, config)
        alice.initialize()
        val identity = assertNotNull(reopen().identity.identity()).publicKey
        database.closeOpenDrivers()
        driver = database.open()
        val before = driver.dump()

        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { reopen(StaticStorageKeyProvider(TestKeys.B)) }
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { reopen(TestKeys.missing) }
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { reopen(StaticStorageKeyProvider(TestKeys.C)) }
        val throwing = object : StorageKeyProvider {
            override suspend fun loadOrCreateKey(): StorageEncryptionKey = error("keystore locked")
            override suspend fun key(id: StorageKeyId): StorageEncryptionKey = error("keystore locked")
            override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey = error("keystore locked")
            override suspend fun removeKey(id: StorageKeyId): Boolean = error("keystore locked")
        }
        val failure = assertFailsWith<StorageEncryptionException.KeyUnavailable> { reopen(throwing) }
        assertEquals("keystore locked", failure.cause?.message)
        assertEquals(before, driver.dump(), "a failed open changes nothing")

        // The right key still opens it: nothing was regenerated or lost.
        val storage = reopen()
        assertContentEquals(identity, storage.identity.identity()?.publicKey)
        SecureMessageClient(ALICE, storage, engine, network, config).initialize()
        assertEquals(before, driver.dump())
    }

    @Test
    fun recordsOfAnotherKeyIdAreKeyUnavailable() = runTest {
        populate(reopen())
        // A session sealed with key C (ID 2) in a database bound to key A (ID 1).
        database.closeOpenDrivers()
        val other = TestDatabase()
        try {
            val otherStorage = SqlDelightClientStorage.open(other.open(), StaticStorageKeyProvider(TestKeys.C))
            otherStorage.sessions.store(SecureSession(BOB, SESSION_MARKER))
            val foreign = other.open().blob("SELECT sealed_state FROM session")
            val storage = reopen()
            driver.exec("UPDATE session SET sealed_state = ? WHERE remote_user_id = 'bob'", foreign)
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { storage.sessions.load(BOB) }
            // Even a provider that knows key C is not asked: the database uses key A only.
            val both = reopen(StaticStorageKeyProvider(TestKeys.A, TestKeys.C))
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { both.sessions.load(BOB) }
        } finally {
            other.close()
        }
    }

    private class Kind(val name: String, val table: String, val column: String, val where: String, val read: suspend (ClientStorage) -> Any?)

    private val kinds = listOf(
        Kind("identity", "local_identity", "sealed_identity", "id = 0") { it.identity.identity() },
        Kind("signed prekey", "signed_pre_key", "sealed_key_pair", "id = 1") { it.preKeys.signedPreKey(SignedPreKeyId(1)) },
        Kind("one-time prekey", "one_time_pre_key", "sealed_key_pair", "id = 10") { it.preKeys.oneTimePreKey(OneTimePreKeyId(10)) },
        Kind("session", "session", "sealed_state", "remote_user_id = 'bob'") { it.sessions.load(BOB) },
        Kind("pending", "pending_outbound_message", "sealed_frame", "recipient_user_id = 'bob' AND sequence = 1") {
            it.pendingOutbound.get(BOB, messageId(1))
        },
    )

    @Test
    fun corruptedRecordsFailClosed() = runTest {
        populate(reopen())
        for (kind in kinds) {
            val original = driver.blob("SELECT ${kind.column} FROM ${kind.table} WHERE ${kind.where}")
            val corruptions = listOf(
                "nonce" to original.flipped(10),
                "ciphertext" to original.flipped(22),
                "tag" to original.flipped(original.size - 1),
                "version" to original.copyOf().also { it[4] = 2 },
                "algorithm" to original.copyOf().also { it[5] = 9 },
                "key ID" to original.flipped(9),
                "truncated" to original.copyOf(original.size - 1),
                "truncated header" to original.copyOf(8),
                "plaintext" to SECRET_MESSAGE,
            )
            for ((what, bytes) in corruptions) {
                driver.exec("UPDATE ${kind.table} SET ${kind.column} = ? WHERE ${kind.where}", bytes)
                val storage = reopen()
                assertFailsWith<StorageEncryptionException>("${kind.name}: $what") { kind.read(storage) }
            }
            driver.exec("UPDATE ${kind.table} SET ${kind.column} = ? WHERE ${kind.where}", original)
            assertNotNull(kind.read(reopen()))
        }
    }

    @Test
    fun copiedRowsFailAuthentication() = runTest {
        populate(reopen())
        val storage = reopen()
        fun copy(table: String, column: String, from: String, to: String) =
            driver.exec("UPDATE $table SET $column = (SELECT $column FROM $table WHERE $from) WHERE $to")

        copy("signed_pre_key", "sealed_key_pair", "id = 1", "id = 2")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.preKeys.signedPreKey(SignedPreKeyId(2)) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.preKeys.currentSignedPreKey() }

        copy("one_time_pre_key", "sealed_key_pair", "id = 10", "id = 11")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.preKeys.oneTimePreKey(OneTimePreKeyId(11)) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.preKeys.publicOneTimePreKeys() }

        copy("session", "sealed_state", "remote_user_id = 'bob'", "remote_user_id = 'carol'")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.sessions.load(CAROL) }

        // Bob M1 over Bob M2, then Bob M1 over Carol M1.
        val bobM1 = "recipient_user_id = 'bob' AND sequence = 1"
        copy("pending_outbound_message", "sealed_frame", bobM1, "recipient_user_id = 'bob' AND sequence = 2")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.pendingOutbound.get(BOB, messageId(2)) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.pendingOutbound.page(0, Int.MAX_VALUE, BOB) }
        copy("pending_outbound_message", "sealed_frame", bobM1, "recipient_user_id = 'carol'")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.pendingOutbound.get(CAROL, messageId(1)) }

        // Across record types: the identity record in a one-time prekey row, and the reverse.
        val identity = driver.blob("SELECT sealed_identity FROM local_identity")
        val oneTime = driver.blob("SELECT sealed_key_pair FROM one_time_pre_key WHERE id = 10")
        driver.exec("UPDATE one_time_pre_key SET sealed_key_pair = ? WHERE id = 10", identity)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.preKeys.oneTimePreKey(OneTimePreKeyId(10)) }
        driver.exec("UPDATE local_identity SET sealed_identity = ?", oneTime)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.identity.identity() }
        // The key check record is no identity either.
        driver.exec("UPDATE local_identity SET sealed_identity = (SELECT key_check FROM storage_encryption)")
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { storage.identity.identity() }
    }

    @Test
    fun corruptedIdentityIsNeverReplaced() = runTest {
        SecureMessageClient(BOB, reopen(), engine, network, config).initialize()
        val corrupted = driver.blob("SELECT sealed_identity FROM local_identity").flipped(30)
        driver.exec("UPDATE local_identity SET sealed_identity = ?", corrupted)
        val before = driver.dump()

        val bob = SecureMessageClient(BOB, reopen(), engine, network, config)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob.initialize() }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { bob.currentPreKeyBundle() }
        assertEquals(before, driver.dump(), "no new identity, no new prekeys")
    }

    /** Alice on encrypted storage with a session to Bob, and Bob's client. */
    private suspend fun aliceWithSession(): Pair<SqlDelightClientStorage, SecureMessageClient> {
        val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, network, config)
        bob.initialize()
        network.publish(bob)
        val aliceStorage = reopen()
        val alice = SecureMessageClient(ALICE, aliceStorage, engine, network, config)
        alice.initialize()
        network.publish(alice)
        alice.send(BOB, "hello".encodeToByteArray())
        network.receive(BOB).let { bob.acceptAll(it) }
        network.receive(ALICE).let { alice.acceptAll(it) }
        return aliceStorage to bob
    }

    @Test
    fun corruptedSessionIsNotMissing() = runTest {
        val (_, bob) = aliceWithSession()
        bob.send(ALICE, "to alice".encodeToByteArray())
        val incoming = network.receive(ALICE).single()
        driver.exec("UPDATE session SET sealed_state = ?", driver.blob("SELECT sealed_state FROM session").flipped(40))
        val before = driver.dump()

        val alice = SecureMessageClient(ALICE, reopen(), engine, network, config)
        // No new X3DH session in place of the unreadable one, and nothing handed to the transport.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice.send(BOB, "again".encodeToByteArray()) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { alice.decrypt(incoming) }
        assertEquals(0, network.waiting(BOB))
        assertEquals(before, driver.dump())
    }

    @Test
    fun corruptedPendingMessageIsNotResent() = runTest {
        aliceWithSession()
        val alice = SecureMessageClient(ALICE, reopen(), engine, network, config)
        alice.send(BOB, SECRET_MESSAGE)
        network.receive(BOB) // lost
        assertNoPlaintext(SECRET_MESSAGE)
        driver.exec("UPDATE pending_outbound_message SET sealed_frame = ?", driver.blob("SELECT sealed_frame FROM pending_outbound_message").flipped(30))
        val before = driver.dump()

        val restarted = SecureMessageClient(ALICE, reopen(), engine, network, config)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { restarted.retryPendingMessages(BOB) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { restarted.pendingMessages(limit = 100, recipient = BOB).messages }
        assertEquals(0, network.waiting(BOB))
        assertEquals(before, driver.dump())
    }

    @Test
    fun corruptedSignedPreKeyAcceptsNoInitiation() = runTest {
        val bobStorage = reopen()
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)
        val carol = SecureMessageClient(CAROL, InMemoryClientStorage(), engine, network, config)
        carol.initialize()
        carol.send(BOB, "hi".encodeToByteArray())
        driver.exec("UPDATE signed_pre_key SET sealed_key_pair = ?", driver.blob("SELECT sealed_key_pair FROM signed_pre_key").flipped(25))
        val before = driver.dump()

        val restarted = SecureMessageClient(BOB, reopen(), engine, network, config)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { restarted.decrypt(network.receive(BOB).single()) }
        assertEquals(before, driver.dump(), "no session, no pin, no one-time prekey removed")
        assertEquals(0, network.waiting(CAROL), "no acknowledgement")
    }

    @Test
    fun encryptionFailuresRollBack() = runTest {
        // Identity, signed and one-time prekeys: initialize writes all or nothing.
        for (kind in listOf("identity", "signedPreKey", "oneTimePreKey")) {
            val records = mutableListOf<FailingRecords>()
            val storage = reopen(records = records)
            records.single().failing = setOf(kind)
            assertFailsWith<IllegalStateException>(kind) { SecureMessageClient(BOB, storage, engine, network, config).initialize() }
            assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM local_identity"), kind)
            assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM signed_pre_key"), kind)
            assertEquals(listOf(0L), driver.longs("SELECT count(*) FROM one_time_pre_key"), kind)
            assertEquals(listOf(null), driver.longs("SELECT highest_signed_pre_key_id FROM pre_key_state"), kind)
        }

        // Session and pending message: a send writes both or nothing, and hands nothing over.
        val bob = SecureMessageClient(BOB, InMemoryClientStorage(), engine, network, config)
        bob.initialize()
        network.publish(bob)
        for (kind in listOf("session", "pending")) {
            val records = mutableListOf<FailingRecords>()
            val storage = reopen(records = records)
            val alice = SecureMessageClient(ALICE, storage, engine, network, config)
            alice.initialize()
            val before = driver.dump()
            records.single().failing = setOf(kind)
            assertFailsWith<IllegalStateException>(kind) { alice.send(BOB, SECRET_MESSAGE) }
            assertEquals(before, driver.dump(), kind)
            assertEquals(0, network.waiting(BOB), kind)
            records.single().failing = emptySet()
            alice.send(BOB, SECRET_MESSAGE)
            assertEquals(1, network.waiting(BOB))
            network.receive(BOB)
        }
    }

    @Test
    fun reliabilityWorksOnEncryptedStorage() = runTest {
        val (_, bob) = aliceWithSession()
        suspend fun alice() = SecureMessageClient(ALICE, reopen(), engine, network, config)
        val sent = alice().send(BOB, SECRET_MESSAGE)
        network.receive(BOB) // lost in transit
        assertNoPlaintext(SECRET_MESSAGE)

        assertEquals(listOf(sent.id), alice().retryPendingMessages(BOB))
        val received = bob.accept(network.receive(BOB).single())
        assertEquals(sent.id, received.id)
        assertContentEquals(SECRET_MESSAGE, received.plaintext)
        assertTrue(assertIs<ReceiveResult.Acknowledgement>(alice().decrypt(network.receive(ALICE).single())).cleared)
        assertEquals(emptyList(), alice().pendingMessages(limit = 100, recipient = BOB).messages)
    }

    @Test
    fun unknownMarkerAndUnboundRecordsFailClosed() = runTest {
        populate(reopen())
        driver.exec("UPDATE storage_encryption SET format = 7")
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> { reopen() }

        driver.exec("UPDATE storage_encryption SET format = 1, key_id = NULL")
        val before = driver.dump()
        // Records but no bound key: never bind a (possibly new) key over them.
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { reopen() }
        assertEquals(before, driver.dump())
    }
}
