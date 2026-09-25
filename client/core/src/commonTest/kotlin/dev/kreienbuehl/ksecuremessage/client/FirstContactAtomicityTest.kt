package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolException
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Accepting a first-contact message stores the session, removes the one-time
 * prekey and pins the sender's identity in one transaction: all happen, or
 * none.
 */
class FirstContactAtomicityTest {
    private val engine: ProtocolEngine = KodiumProtocolEngine()
    private val network = FakeNetwork()
    private val storage = InMemoryClientStorage()
    private val failing = FailingClientStorage(storage)
    private val oneTimePreKey = OneTimePreKeyId(0)

    /** Bob with fault-injecting storage, and Alice's first message to him. */
    private suspend fun firstContact(): Pair<SecureMessageClient, EncryptedEnvelope> {
        val config = PreKeyConfiguration(oneTimePreKeyTarget = 2)
        val bob = SecureMessageClient(BOB, failing, engine, network, config).apply { initialize() }
        network.publish(bob)
        val alice = SecureMessageClient(ALICE, InMemoryClientStorage(), engine, network, config).apply { initialize() }
        alice.sendRaw(BOB, "Hello Bob".encodeToByteArray())
        return bob to network.receive(BOB).single()
    }

    private suspend fun assertNothingCommitted() {
        assertNull(storage.sessions.load(ALICE), "no session")
        assertNull(storage.remoteIdentities.identityKey(ALICE), "no pinned identity")
        assertNotNull(storage.preKeys.oneTimePreKey(oneTimePreKey), "one-time prekey still available")
        assertEquals(2, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun successCommitsSessionAndRemoval() = runTest {
        val (bob, envelope) = firstContact()
        assertEquals("Hello Bob", bob.decryptRaw(envelope).decodeToString())

        assertNotNull(storage.sessions.load(ALICE))
        assertNull(storage.preKeys.oneTimePreKey(oneTimePreKey))
        assertNotNull(storage.remoteIdentities.identityKey(ALICE))
    }

    @Test
    fun tamperedMessageCommitsNothing() = runTest {
        val (bob, envelope) = firstContact()
        assertFailsWith<ProtocolException> { bob.decryptRaw(envelope.tampered()) }
        assertNothingCommitted()
    }

    @Test
    fun sessionStoreFailureKeepsTheOneTimePreKey() = runTest {
        val (bob, envelope) = firstContact()
        failing.failSessionStore = true
        assertFailsWith<StorageFailure> { bob.decryptRaw(envelope) }
        assertNothingCommitted()

        failing.failSessionStore = false
        assertEquals("Hello Bob", bob.decryptRaw(envelope).decodeToString())
    }

    @Test
    fun removalFailureRollsBackTheStoredSession() = runTest {
        val (bob, envelope) = firstContact()
        failing.failOneTimePreKeyRemoval = true
        assertFailsWith<StorageFailure> { bob.decryptRaw(envelope) }
        assertNothingCommitted()

        failing.failOneTimePreKeyRemoval = false
        assertEquals("Hello Bob", bob.decryptRaw(envelope).decodeToString())
        assertNull(storage.preKeys.oneTimePreKey(oneTimePreKey))
    }

    @Test
    fun pinFailureRollsBackSessionAndRemoval() = runTest {
        val (bob, envelope) = firstContact()
        failing.failRemoteIdentityStore = true
        assertFailsWith<StorageFailure> { bob.decryptRaw(envelope) }
        assertNothingCommitted()

        failing.failRemoteIdentityStore = false
        assertEquals("Hello Bob", bob.decryptRaw(envelope).decodeToString())
        assertNotNull(storage.remoteIdentities.identityKey(ALICE))
    }
}
