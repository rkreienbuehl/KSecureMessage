package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.SignedPreKeyInfo
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/**
 * Behavior every [ClientStorage] implementation must have. Subclass it in an
 * adapter's tests. Key material is fake: storage never interprets it.
 */
abstract class ClientStorageContractTest {
    /** Returns a new, empty storage. */
    protected abstract suspend fun newStorage(): ClientStorage

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    private class Failure : Exception()

    @Test
    fun identityIsStoredOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.identity.identity())

        storage.identity.store(identity(1))
        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)

        assertFailsWith<IllegalStateException> { storage.identity.store(identity(2)) }
        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
    }

    @Test
    fun deviceAuthenticationKeyIsStoredOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.deviceAuthentication.keyPair())
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey(), "a new storage has no pre-milestone-12 identity")

        storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        assertContentEquals(bytes(3), storage.deviceAuthentication.keyPair()?.publicKey)
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)

        assertFailsWith<IllegalStateException> { storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(4), bytes(-4))) }
        assertFailsWith<IllegalStateException>("an identical key is refused too") {
            storage.deviceAuthentication.store(DeviceAuthenticationKeyPair(bytes(3), bytes(-3)))
        }
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey)
        assertFalse(storage.deviceAuthentication.awaitsUpgradeKey())
    }

    @Test
    fun deviceAuthenticationKeyIsCopiedAndRolledBack() = runTest {
        val storage = newStorage()
        val keyPair = DeviceAuthenticationKeyPair(bytes(3), bytes(-3))
        assertFailsWith<Failure> {
            storage.transaction {
                identity.store(identity(1))
                deviceAuthentication.store(keyPair)
                assertContentEquals(bytes(-3), deviceAuthentication.keyPair()?.privateKey, "visible inside the transaction")
                throw Failure()
            }
        }
        assertNull(storage.deviceAuthentication.keyPair())
        assertNull(storage.identity.identity())

        storage.transaction {
            identity.store(identity(1))
            deviceAuthentication.store(keyPair)
        }
        keyPair.privateKey.fill(0)
        storage.deviceAuthentication.keyPair()!!.privateKey.fill(0)
        assertContentEquals(bytes(-3), storage.deviceAuthentication.keyPair()?.privateKey, "stored bytes are not aliased")
    }

    @Test
    fun remoteIdentityIsPinnedOnceAndNeverReplaced() = runTest {
        val storage = newStorage()
        assertNull(storage.remoteIdentities.identityKey(alice))

        storage.remoteIdentities.store(alice, bytes(1))
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice))

        storage.remoteIdentities.store(alice, bytes(1))
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice), "same key again is a no-op")

        assertFailsWith<IllegalStateException> { storage.remoteIdentities.store(alice, bytes(2)) }
        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun remoteIdentitiesArePerDevice() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        storage.remoteIdentities.store(bob, bytes(1))
        storage.remoteIdentities.store(bobPhone, bytes(2))

        assertContentEquals(bytes(1), storage.remoteIdentities.identityKey(bob))
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(bobPhone))
        assertNull(storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun rolledBackTransactionLeavesNoPin() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                remoteIdentities.store(alice, bytes(1))
                assertContentEquals(bytes(1), remoteIdentities.identityKey(alice))
                throw Failure()
            }
        }
        assertNull(storage.remoteIdentities.identityKey(alice))

        // Not pinned, so a different key can still be the first one.
        storage.remoteIdentities.store(alice, bytes(2))
        assertContentEquals(bytes(2), storage.remoteIdentities.identityKey(alice))
    }

    @Test
    fun sessionInitiationsAreRetiredPerDevice() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(1)))

        storage.sessionInitiations.retire(bob, initiation(1), null)
        storage.sessionInitiations.retire(bob, initiation(1), null)
        storage.sessionInitiations.retire(bob, initiation(2), SignedPreKeyId(3))

        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(1)))
        assertTrue(storage.sessionInitiations.isRetired(bob, SessionInitiationId(bytes(1))), "compared by content")
        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(2)))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(3)))
        assertFalse(storage.sessionInitiations.isRetired(bobPhone, initiation(1)))
        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
    }

    @Test
    fun rolledBackTransactionRetiresNothing() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(1))
                sessions.store(SecureSession(alice, bytes(1)))
                assertTrue(sessionInitiations.isRetired(alice, initiation(1)))
                throw Failure()
            }
        }
        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
        assertNull(storage.sessions.load(alice))
    }

    @Test
    fun sessionsAreStoredReplacedAndRemoved() = runTest {
        val storage = newStorage()
        storage.sessions.store(SecureSession(alice, bytes(1)))
        storage.sessions.store(SecureSession(bob, bytes(2)))
        storage.sessions.store(SecureSession(alice, bytes(3)))

        assertContentEquals(bytes(3), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(2), storage.sessions.load(bob)?.state)

        storage.sessions.remove(alice)
        assertNull(storage.sessions.load(alice))
        assertNotNull(storage.sessions.load(bob))
    }

    @Test
    fun replacedSignedPreKeysStayAvailableById() = runTest {
        val storage = newStorage()
        assertNull(storage.preKeys.currentSignedPreKey())
        assertNull(storage.preKeys.highestSignedPreKeyId())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))

        val current = assertNotNull(storage.preKeys.currentSignedPreKey())
        assertEquals(SignedPreKeyId(1), current.id)
        assertContentEquals(bytes(12), current.signature)
        assertContentEquals(bytes(-1), current.privateKey)
        assertContentEquals(bytes(0), storage.preKeys.signedPreKey(SignedPreKeyId(0))?.publicKey)
        assertEquals(SignedPreKeyId(1), storage.preKeys.highestSignedPreKeyId())
    }

    @Test
    fun signedPreKeyIdsCannotBeReused() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5), at(5))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5), at(5)) }
        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(4), at(4)) }
        assertEquals(SignedPreKeyId(5), storage.preKeys.currentSignedPreKey()?.id)
    }

    @Test
    fun signedPreKeyLifecycleTimestampsAreRecorded() = runTest {
        val storage = newStorage()
        assertEquals(emptyList(), storage.preKeys.signedPreKeyInfos())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(10))
        assertEquals(listOf(SignedPreKeyInfo(SignedPreKeyId(0), true, at(10), null)), storage.preKeys.signedPreKeyInfos())

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(20))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(30))
        assertEquals(
            listOf(
                SignedPreKeyInfo(SignedPreKeyId(0), false, at(10), at(20)),
                SignedPreKeyInfo(SignedPreKeyId(1), false, at(20), at(30)),
                SignedPreKeyInfo(SignedPreKeyId(2), true, at(30), null),
            ),
            storage.preKeys.signedPreKeyInfos(),
        )
        assertEquals(SignedPreKeyInfo(SignedPreKeyId(1), false, at(20), at(30)), storage.preKeys.signedPreKeyInfo(SignedPreKeyId(1)))
        assertNull(storage.preKeys.signedPreKeyInfo(SignedPreKeyId(3)))
    }

    @Test
    fun stampingDoesNotChangeKeysThatHaveTimestamps() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(10))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(20))
        val before = storage.preKeys.signedPreKeyInfos()

        storage.preKeys.stampLegacySignedPreKeys(at(99))
        assertEquals(before, storage.preKeys.signedPreKeyInfos())
    }

    @Test
    fun removedSignedPreKeyIsGoneButItsIdStaysUsed() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(2))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.removeSignedPreKey(SignedPreKeyId(2)) }
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(2)))

        storage.preKeys.removeSignedPreKey(SignedPreKeyId(0))
        storage.preKeys.removeSignedPreKey(SignedPreKeyId(0))
        storage.preKeys.removeSignedPreKey(SignedPreKeyId(7))
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertNull(storage.preKeys.signedPreKeyInfo(SignedPreKeyId(0)))
        assertEquals(listOf(1, 2), storage.preKeys.signedPreKeyInfos().map { it.id.value })
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(1)))
        assertEquals(SignedPreKeyId(2), storage.preKeys.highestSignedPreKeyId())
        assertEquals(SignedPreKeyId(2), storage.preKeys.currentSignedPreKey()?.id)

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(3)) }
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)), "a deleted ID is never stored again")
    }

    @Test
    fun retiredInitiationsArePrunedPerSignedPreKey() = runTest {
        val storage = newStorage()
        val bobPhone = DeviceAddress(UserId("bob"), DeviceId("phone"))
        storage.sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(1))
        storage.sessionInitiations.retire(bob, initiation(2), SignedPreKeyId(1))
        storage.sessionInitiations.retire(bobPhone, initiation(3), SignedPreKeyId(2))
        storage.sessionInitiations.retire(bob, initiation(4), null)
        // Retiring again keeps the first entry.
        storage.sessionInitiations.retire(bob, initiation(4), SignedPreKeyId(1))
        assertEquals(setOf(SignedPreKeyId(1), SignedPreKeyId(2)), storage.sessionInitiations.retiredSignedPreKeyIds())

        storage.sessionInitiations.removeRetiredFor(SignedPreKeyId(1))

        assertFalse(storage.sessionInitiations.isRetired(alice, initiation(1)))
        assertFalse(storage.sessionInitiations.isRetired(bob, initiation(2)))
        assertTrue(storage.sessionInitiations.isRetired(bobPhone, initiation(3)))
        assertTrue(storage.sessionInitiations.isRetired(bob, initiation(4)), "entries without a signed prekey are kept")
        assertEquals(setOf(SignedPreKeyId(2)), storage.sessionInitiations.retiredSignedPreKeyIds())
    }

    @Test
    fun rolledBackTransactionKeepsSignedPreKeysAndRetiredInitiations() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
        storage.sessionInitiations.retire(alice, initiation(1), SignedPreKeyId(0))
        val before = storage.preKeys.signedPreKeyInfos()

        assertFailsWith<Failure> {
            storage.transaction {
                preKeys.removeSignedPreKey(SignedPreKeyId(0))
                sessionInitiations.removeRetiredFor(SignedPreKeyId(0))
                preKeys.storeCurrentSignedPreKey(signedPreKey(2), at(2))
                preKeys.stampLegacySignedPreKeys(at(3))
                throw Failure()
            }
        }
        assertEquals(before, storage.preKeys.signedPreKeyInfos())
        assertNotNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertEquals(SignedPreKeyId(1), storage.preKeys.highestSignedPreKeyId())
        assertTrue(storage.sessionInitiations.isRetired(alice, initiation(1)))
    }

    @Test
    fun oneTimePreKeysAreListedCountedAndRemoved() = runTest {
        val storage = newStorage()
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
        assertNull(storage.preKeys.highestOneTimePreKeyId())

        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2), oneTimePreKey(0), oneTimePreKey(1)))
        assertEquals(3, storage.preKeys.oneTimePreKeyCount())
        val published = storage.preKeys.publicOneTimePreKeys()
        assertEquals(listOf(0, 1, 2), published.map { it.id.value })
        assertContentEquals(bytes(1), published[1].publicKey)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(1))?.privateKey)

        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(1))
        assertNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(1)))
        assertEquals(2, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(2), storage.preKeys.highestOneTimePreKeyId(), "removal keeps the high-water mark")
    }

    @Test
    fun oneTimePreKeyIdsCannotBeReused() = runTest {
        val storage = newStorage()
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1)))
        storage.preKeys.removeOneTimePreKey(OneTimePreKeyId(1))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(1))) }
        assertFailsWith<IllegalArgumentException> {
            storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(3), oneTimePreKey(3)))
        }
        assertEquals(1, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(1), storage.preKeys.highestOneTimePreKeyId())

        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2)))
        assertEquals(OneTimePreKeyId(2), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun maxIdIsAccepted() = runTest {
        val storage = newStorage()
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(Int.MAX_VALUE), at(0))
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(Int.MAX_VALUE)))

        assertEquals(SignedPreKeyId(Int.MAX_VALUE), storage.preKeys.highestSignedPreKeyId())
        assertEquals(OneTimePreKeyId(Int.MAX_VALUE), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun successfulTransactionCommitsAllWrites() = runTest {
        val storage = newStorage()
        val result = storage.transaction {
            identity.store(identity(1))
            sessions.store(SecureSession(alice, bytes(1)))
            preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            "done"
        }

        assertEquals("done", result)
        assertNotNull(storage.identity.identity())
        assertNotNull(storage.sessions.load(alice))
        assertNotNull(storage.preKeys.currentSignedPreKey())
        assertEquals(1, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun failedTransactionOnEmptyStorageLeavesItEmpty() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                identity.store(identity(1))
                sessions.store(SecureSession(alice, bytes(1)))
                preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
                throw Failure()
            }
        }

        assertNull(storage.identity.identity())
        assertNull(storage.sessions.load(alice))
        assertNull(storage.preKeys.currentSignedPreKey())
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(0)))
        assertNull(storage.preKeys.highestSignedPreKeyId())
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
        assertNull(storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun failedTransactionRollsBackEveryKindOfChange() = runTest {
        val storage = newStorage()
        storage.transaction {
            identity.store(identity(1))
            sessions.store(SecureSession(alice, bytes(1)))
            sessions.store(SecureSession(bob, bytes(2)))
            preKeys.storeCurrentSignedPreKey(signedPreKey(0), at(0))
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1)))
        }

        assertFailsWith<Failure> {
            storage.transaction {
                sessions.store(SecureSession(alice, bytes(9)))
                sessions.remove(bob)
                preKeys.storeCurrentSignedPreKey(signedPreKey(1), at(1))
                preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(2)))
                throw Failure()
            }
        }

        assertContentEquals(bytes(1), storage.identity.identity()?.publicKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(2), storage.sessions.load(bob)?.state)
        assertEquals(SignedPreKeyId(0), storage.preKeys.currentSignedPreKey()?.id)
        assertNull(storage.preKeys.signedPreKey(SignedPreKeyId(1)))
        assertEquals(SignedPreKeyId(0), storage.preKeys.highestSignedPreKeyId())
        assertNotNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        assertNull(storage.preKeys.oneTimePreKey(OneTimePreKeyId(2)))
        assertEquals(2, storage.preKeys.oneTimePreKeyCount())
        assertEquals(OneTimePreKeyId(1), storage.preKeys.highestOneTimePreKeyId())
    }

    @Test
    fun rejectedWriteInsideTransactionRollsBackEarlierWrites() = runTest {
        val storage = newStorage()
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))

        assertFailsWith<IllegalArgumentException> {
            storage.transaction {
                sessions.store(SecureSession(alice, bytes(1)))
                preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            }
        }
        assertNull(storage.sessions.load(alice))
    }

    @Test
    fun writesAreVisibleInsideTheTransaction() = runTest {
        val storage = newStorage()
        storage.transaction {
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0)))
            assertEquals(1, preKeys.oneTimePreKeyCount())
            preKeys.removeOneTimePreKey(OneTimePreKeyId(0))
            assertNull(preKeys.oneTimePreKey(OneTimePreKeyId(0)))
        }
        assertEquals(0, storage.preKeys.oneTimePreKeyCount())
    }

    @Test
    fun nestedTransactionsJoinTheOuterOne() = runTest {
        val storage = newStorage()
        assertFailsWith<Failure> {
            storage.transaction {
                transaction { sessions.store(SecureSession(alice, bytes(1))) }
                // The storage object itself also joins instead of deadlocking.
                storage.sessions.store(SecureSession(bob, bytes(2)))
                assertNotNull(storage.sessions.load(alice))
                throw Failure()
            }
        }
        assertNull(storage.sessions.load(alice))
        assertNull(storage.sessions.load(bob))
    }

    @Test
    fun storedBytesAreNotAliased() = runTest {
        val storage = newStorage()
        val identity = identity(1)
        val session = SecureSession(alice, bytes(1))
        val oneTimePreKey = oneTimePreKey(0)
        storage.identity.store(identity)
        storage.sessions.store(session)
        storage.preKeys.storeOneTimePreKeys(listOf(oneTimePreKey))

        identity.privateKey.fill(0)
        session.state.fill(0)
        oneTimePreKey.privateKey.fill(0)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))?.privateKey)

        val remoteKey = bytes(5)
        storage.remoteIdentities.store(bob, remoteKey)
        remoteKey.fill(0)
        assertContentEquals(bytes(5), storage.remoteIdentities.identityKey(bob))
        storage.remoteIdentities.identityKey(bob)!!.fill(0)
        assertContentEquals(bytes(5), storage.remoteIdentities.identityKey(bob))

        storage.identity.identity()!!.privateKey.fill(0)
        storage.sessions.load(alice)!!.state.fill(0)
        storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))!!.privateKey.fill(0)
        assertContentEquals(bytes(-1), storage.identity.identity()?.privateKey)
        assertContentEquals(bytes(1), storage.sessions.load(alice)?.state)
        assertContentEquals(bytes(-1), storage.preKeys.oneTimePreKey(OneTimePreKeyId(0))?.privateKey)
    }

    // Message reliability state (docs/message-reliability.md)

    @Test
    fun pendingMessagesAreListedInSendOrderPerRecipient() = runTest {
        val storage = newStorage()
        val first = storage.pendingOutbound.store(bob, messageId(3), bytes(3))
        val other = storage.pendingOutbound.store(alice, messageId(1), bytes(1))
        val second = storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        val third = storage.pendingOutbound.store(bob, messageId(2), bytes(2))

        assertTrue(first < other && other < second && second < third)
        // Send order, not ID order.
        assertEquals(listOf(messageId(3), messageId(1), messageId(2)), storage.pendingOutbound.list(bob).map { it.id })
        assertEquals(listOf(first, second, third), storage.pendingOutbound.list(bob).map { it.sequence })
        assertEquals(listOf(messageId(1)), storage.pendingOutbound.list(alice).map { it.id })
        val loaded = assertNotNull(storage.pendingOutbound.get(bob, messageId(1)))
        assertEquals(bob, loaded.recipient)
        assertEquals(second, loaded.sequence)
        assertContentEquals(bytes(1), loaded.frame)
    }

    @Test
    fun pendingMessagesAreScopedByRecipient() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(alice, messageId(1), bytes(1))
        storage.pendingOutbound.store(bob, messageId(1), bytes(2))

        assertNull(storage.pendingOutbound.get(DeviceAddress(UserId("bob"), DeviceId("phone")), messageId(1)))
        assertTrue(storage.pendingOutbound.remove(bob, messageId(1)))
        assertNull(storage.pendingOutbound.get(bob, messageId(1)))
        assertContentEquals(bytes(1), storage.pendingOutbound.get(alice, messageId(1))?.frame)
    }

    @Test
    fun pendingMessageIsStoredOncePerRecipient() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        assertFailsWith<IllegalArgumentException> { storage.pendingOutbound.store(bob, messageId(1), bytes(2)) }
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)
        assertEquals(1, storage.pendingOutbound.list(bob).size)
    }

    @Test
    fun removingAPendingMessageIsIdempotentAndSequencesAreNotReused() = runTest {
        val storage = newStorage()
        val first = storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        val second = storage.pendingOutbound.store(bob, messageId(2), bytes(2))

        assertTrue(storage.pendingOutbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingOutbound.remove(bob, messageId(2)))
        assertFalse(storage.pendingOutbound.remove(bob, messageId(9)))
        val third = storage.pendingOutbound.store(bob, messageId(3), bytes(3))

        assertTrue(third > second)
        assertEquals(listOf(first, third), storage.pendingOutbound.list(bob).map { it.sequence })
        // The same ID may become pending again once removed.
        storage.pendingOutbound.store(bob, messageId(2), bytes(4))
        assertEquals(listOf(messageId(1), messageId(3), messageId(2)), storage.pendingOutbound.list(bob).map { it.id })
    }

    @Test
    fun processedMessagesAreScopedBySenderAndIdempotent() = runTest {
        val storage = newStorage()
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(1)))

        storage.processedInbound.markProcessed(alice, messageId(1))
        storage.processedInbound.markProcessed(alice, messageId(1))

        assertTrue(storage.processedInbound.isProcessed(alice, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(alice, messageId(2)))
    }

    @Test
    fun rolledBackTransactionLeavesNoReliabilityState() = runTest {
        val storage = newStorage()
        storage.pendingOutbound.store(bob, messageId(1), bytes(1))
        storage.processedInbound.markProcessed(bob, messageId(1))

        assertFailsWith<Failure> {
            storage.transaction {
                pendingOutbound.store(bob, messageId(2), bytes(2))
                assertTrue(pendingOutbound.remove(bob, messageId(1)))
                processedInbound.markProcessed(bob, messageId(2))
                assertTrue(processedInbound.isProcessed(bob, messageId(2)))
                throw Failure()
            }
        }

        assertEquals(listOf(messageId(1)), storage.pendingOutbound.list(bob).map { it.id })
        assertTrue(storage.processedInbound.isProcessed(bob, messageId(1)))
        assertFalse(storage.processedInbound.isProcessed(bob, messageId(2)))
    }

    @Test
    fun pendingFramesAreNotAliased() = runTest {
        val storage = newStorage()
        val frame = bytes(1)
        storage.pendingOutbound.store(bob, messageId(1), frame)
        frame.fill(0)
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)

        storage.pendingOutbound.get(bob, messageId(1))!!.frame.fill(0)
        storage.pendingOutbound.list(bob).single().frame.fill(0)
        assertContentEquals(bytes(1), storage.pendingOutbound.get(bob, messageId(1))?.frame)
    }

    companion object {
        /** 32 fake key bytes derived from [seed]. Negative seeds stand for private keys. */
        fun bytes(seed: Int): ByteArray = ByteArray(32) { (seed * 31 + it).toByte() }

        fun identity(seed: Int) = LocalIdentity(publicKey = bytes(seed), privateKey = bytes(-seed))

        fun signedPreKey(id: Int) = SignedPreKeyPair(SignedPreKeyId(id), bytes(id), bytes(id + 11), bytes(-1))

        fun oneTimePreKey(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), bytes(id), bytes(-1))

        fun initiation(seed: Int) = SessionInitiationId(bytes(seed))

        fun messageId(seed: Int) = LogicalMessageId.fromByteArray(ByteArray(LogicalMessageId.SIZE) { (seed + it).toByte() })

        /** Whole milliseconds: adapters may store timestamps at that precision. */
        fun at(seconds: Int): Instant = Instant.fromEpochMilliseconds(1_700_000_000_000L + seconds * 1_000L)
    }
}
