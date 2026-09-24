package dev.kreienbuehl.ksecuremessage.storage.sqldelight

import dev.kreienbuehl.ksecuremessage.client.PreKeyConfiguration
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.SecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyBundle
import dev.kreienbuehl.ksecuremessage.model.PreKeyPublication
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.PreKeyStore
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.bytes
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.identity
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.oneTimePreKey
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest.Companion.signedPreKey
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private val ALICE = DeviceAddress(UserId("alice"), DeviceId("phone"))
private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))

/** Closes and reopens the database file between steps, like an application restart. */
class SqlDelightPersistenceTest {
    private val database = TestDatabase()
    private val engine = KodiumProtocolEngine()
    private val network = Relay()

    @AfterTest
    fun close() = database.close()

    /** Closes the open connection and opens a new one on the same file. */
    private fun reopen(): SqlDelightClientStorage {
        database.closeOpenDrivers()
        return SqlDelightClientStorage(database.open())
    }

    private suspend fun ClientStorage.oneTimePreKeyIds() = preKeys.publicOneTimePreKeys().map { it.id.value }

    @Test
    fun dataSurvivesReopen() = runTest {
        val before = reopen()
        before.identity.store(identity(1))
        before.preKeys.storeCurrentSignedPreKey(signedPreKey(0))
        before.preKeys.storeCurrentSignedPreKey(signedPreKey(1))
        before.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1), oneTimePreKey(2)))
        before.preKeys.removeOneTimePreKey(OneTimePreKeyId(2))
        before.sessions.store(SecureSession(ALICE, bytes(7)))

        val after = reopen()
        assertContentEquals(bytes(-1), after.identity.identity()?.privateKey)
        assertEquals(SignedPreKeyId(1), after.preKeys.currentSignedPreKey()?.id)
        assertContentEquals(bytes(0), after.preKeys.signedPreKey(SignedPreKeyId(0))?.publicKey)
        assertEquals(SignedPreKeyId(1), after.preKeys.highestSignedPreKeyId())
        assertEquals(listOf(0, 1), after.oneTimePreKeyIds())
        assertEquals(OneTimePreKeyId(2), after.preKeys.highestOneTimePreKeyId())
        assertContentEquals(bytes(7), after.sessions.load(ALICE)?.state)
    }

    @Test
    fun rolledBackTransactionLeavesNothingOnDisk() = runTest {
        val before = reopen()
        before.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))

        assertFailsWith<IllegalStateException> {
            before.transaction {
                identity.store(identity(1))
                sessions.store(SecureSession(ALICE, bytes(1)))
                preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(1)))
                error("fail")
            }
        }

        val after = reopen()
        assertNull(after.identity.identity())
        assertNull(after.sessions.load(ALICE))
        assertEquals(listOf(0), after.oneTimePreKeyIds())
        assertEquals(OneTimePreKeyId(0), after.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun clientContinuesAfterRestart() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 3)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config)
        alice.initialize()
        network.publish(alice)

        val bobStorage = reopen()
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)
        val identity = assertNotNull(bobStorage.identity.identity())
        val signedPreKeyId = bob.currentPreKeyBundle().signedPreKey.id

        alice.send(BOB, "Hello Bob".encodeToByteArray())
        assertEquals("Hello Bob", bob.receiveText())
        bob.send(ALICE, "Hello Alice".encodeToByteArray())
        assertEquals("Hello Alice", alice.receiveText())
        assertEquals(listOf(1, 2), bobStorage.oneTimePreKeyIds())

        val restartedStorage = reopen()
        val restarted = SecureMessageClient(BOB, restartedStorage, engine, network, config)
        restarted.initialize()

        val after = assertNotNull(restartedStorage.identity.identity())
        assertContentEquals(identity.publicKey, after.publicKey)
        assertContentEquals(identity.privateKey, after.privateKey)
        assertEquals(signedPreKeyId, restarted.currentPreKeyBundle().signedPreKey.id)
        assertEquals(listOf(1, 2, 3), restartedStorage.oneTimePreKeyIds(), "only the consumed key is replaced")

        alice.send(BOB, "Still there?".encodeToByteArray())
        assertEquals("Still there?", restarted.receiveText())
        restarted.send(ALICE, "Yes".encodeToByteArray())
        assertEquals("Yes", alice.receiveText())
    }

    @Test
    fun failedOneTimePreKeyRemovalRollsBackTheSession() = runTest {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 2)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config)
        alice.initialize()

        val bobStorage = FailingRemoval(reopen())
        val bob = SecureMessageClient(BOB, bobStorage, engine, network, config)
        bob.initialize()
        network.publish(bob)

        alice.send(BOB, "Hello Bob".encodeToByteArray())
        val envelope = network.receive(BOB).single()
        assertFailsWith<IllegalStateException> { bob.decrypt(envelope) }

        val after = reopen()
        assertNull(after.sessions.load(ALICE))
        assertNotNull(after.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
    }

    private suspend fun SecureMessageClient.receiveText(): String =
        decrypt(network.receive(localAddress).single()).decodeToString()

    private class Relay : SecureMessageTransport {
        private val bundles = mutableMapOf<DeviceAddress, PreKeyBundle>()
        private val mailboxes = mutableMapOf<DeviceAddress, MutableList<EncryptedEnvelope>>()

        suspend fun publish(client: SecureMessageClient) {
            bundles[client.localAddress] =
                client.currentPreKeyBundle().copy(oneTimePreKey = client.publicOneTimePreKeys().first())
        }

        override suspend fun publishPreKeys(publication: PreKeyPublication) =
            error("These tests set bundles directly, see publish")

        override suspend fun fetchPreKeyBundle(address: DeviceAddress) = bundles.getValue(address)

        override suspend fun send(envelope: EncryptedEnvelope) {
            mailboxes.getOrPut(envelope.recipient) { mutableListOf() }.add(envelope)
        }

        override suspend fun receive(address: DeviceAddress) = mailboxes.remove(address)?.toList().orEmpty()
    }

    /** Fails every one-time prekey removal inside a transaction. */
    private class FailingRemoval(private val delegate: ClientStorage) : ClientStorage by delegate {
        override suspend fun <T> transaction(block: suspend ClientStorage.() -> T): T = delegate.transaction {
            val tx = this
            object : ClientStorage by tx {
                override val preKeys: PreKeyStore = object : PreKeyStore by tx.preKeys {
                    override suspend fun removeOneTimePreKey(id: OneTimePreKeyId) = error("Injected failure")
                }
            }.block()
        }
    }
}
