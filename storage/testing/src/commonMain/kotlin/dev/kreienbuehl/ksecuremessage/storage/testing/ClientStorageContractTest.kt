package dev.kreienbuehl.ksecuremessage.storage.testing

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SessionInitiationId
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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

        storage.sessionInitiations.retire(bob, initiation(1))
        storage.sessionInitiations.retire(bob, initiation(1))
        storage.sessionInitiations.retire(bob, initiation(2))

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
                sessionInitiations.retire(alice, initiation(1))
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

        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(0))
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(1))

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
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5))

        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(5)) }
        assertFailsWith<IllegalArgumentException> { storage.preKeys.storeCurrentSignedPreKey(signedPreKey(4)) }
        assertEquals(SignedPreKeyId(5), storage.preKeys.currentSignedPreKey()?.id)
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
        storage.preKeys.storeCurrentSignedPreKey(signedPreKey(Int.MAX_VALUE))
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
            preKeys.storeCurrentSignedPreKey(signedPreKey(0))
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
                preKeys.storeCurrentSignedPreKey(signedPreKey(0))
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
            preKeys.storeCurrentSignedPreKey(signedPreKey(0))
            preKeys.storeOneTimePreKeys(listOf(oneTimePreKey(0), oneTimePreKey(1)))
        }

        assertFailsWith<Failure> {
            storage.transaction {
                sessions.store(SecureSession(alice, bytes(9)))
                sessions.remove(bob)
                preKeys.storeCurrentSignedPreKey(signedPreKey(1))
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

    companion object {
        /** 32 fake key bytes derived from [seed]. Negative seeds stand for private keys. */
        fun bytes(seed: Int): ByteArray = ByteArray(32) { (seed * 31 + it).toByte() }

        fun identity(seed: Int) = LocalIdentity(publicKey = bytes(seed), privateKey = bytes(-seed))

        fun signedPreKey(id: Int) = SignedPreKeyPair(SignedPreKeyId(id), bytes(id), bytes(id + 11), bytes(-1))

        fun oneTimePreKey(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), bytes(id), bytes(-1))

        fun initiation(seed: Int) = SessionInitiationId(bytes(seed))
    }
}
