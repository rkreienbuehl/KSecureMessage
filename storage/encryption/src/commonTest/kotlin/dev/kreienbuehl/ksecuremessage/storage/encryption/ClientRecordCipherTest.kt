package dev.kreienbuehl.ksecuremessage.storage.encryption

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

private val BOB = DeviceAddress(UserId("bob"), DeviceId("laptop"))
private val CAROL = DeviceAddress(UserId("carol"), DeviceId("tablet"))

class ClientRecordCipherTest {
    private val cipher = ClientRecordCipher(testKey(1, 0))
    private val m1 = LogicalMessageId(Uuid.fromLongs(1, 1))
    private val m2 = LogicalMessageId(Uuid.fromLongs(1, 2))

    private fun bytes(seed: Int, size: Int = 32) = ByteArray(size) { (seed + it).toByte() }

    private fun signed(id: Int) = SignedPreKeyPair(SignedPreKeyId(id), bytes(id), bytes(id + 1, 64), bytes(id + 2))
    private fun oneTime(id: Int) = OneTimePreKeyPair(OneTimePreKeyId(id), bytes(id), bytes(id + 3))

    @Test
    fun recordsRoundtrip() = runTest {
        val identity = cipher.openIdentity(cipher.sealIdentity(LocalIdentity(bytes(1), bytes(2, 64))))
        assertContentEquals(bytes(1), identity.publicKey)
        assertContentEquals(bytes(2, 64), identity.privateKey)

        val spk = cipher.openSignedPreKey(SignedPreKeyId(3), cipher.sealSignedPreKey(signed(3)))
        assertEquals(SignedPreKeyId(3), spk.id)
        assertContentEquals(bytes(3), spk.publicKey)
        assertContentEquals(bytes(4, 64), spk.signature)
        assertContentEquals(bytes(5), spk.privateKey)

        val otpk = cipher.openOneTimePreKey(OneTimePreKeyId(9), cipher.sealOneTimePreKey(oneTime(9)))
        assertContentEquals(bytes(9), otpk.publicKey)
        assertContentEquals(bytes(12), otpk.privateKey)

        val session = cipher.openSession(BOB, cipher.sealSession(SecureSession(BOB, bytes(7, 100))))
        assertEquals(BOB, session.remote)
        assertContentEquals(bytes(7, 100), session.state)

        assertContentEquals(bytes(8, 5), cipher.openPendingFrame(BOB, m1, cipher.sealPendingFrame(BOB, m1, bytes(8, 5))))
        cipher.verifyKeyCheck(cipher.sealKeyCheck())
    }

    @Test
    fun sealedRecordsDoNotContainPlaintext() = runTest {
        val secret = "super-secret-pending-message".encodeToByteArray()
        val sealed = cipher.sealPendingFrame(BOB, m1, secret)
        assertFalse(sealed.toHex().contains(secret.toHex()))
        val privateKey = ByteArray(32) { 0x5A }
        assertFalse(cipher.sealIdentity(LocalIdentity(bytes(1), privateKey)).toHex().contains(privateKey.toHex()))
    }

    @Test
    fun rowSubstitutionsFail() = runTest {
        val spk1 = cipher.sealSignedPreKey(signed(1))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openSignedPreKey(SignedPreKeyId(2), spk1) }

        val otpk1 = cipher.sealOneTimePreKey(oneTime(1))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openOneTimePreKey(OneTimePreKeyId(2), otpk1) }

        val bobSession = cipher.sealSession(SecureSession(BOB, bytes(1, 80)))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openSession(CAROL, bobSession) }

        val bobM1 = cipher.sealPendingFrame(BOB, m1, bytes(1, 40))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openPendingFrame(BOB, m2, bobM1) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openPendingFrame(CAROL, m1, bobM1) }
    }

    @Test
    fun crossTypeSubstitutionsFailEvenWithEqualSizes() = runTest {
        // An identity record and a one-time prekey record with the same plaintext layout and sizes.
        val identity = cipher.sealIdentity(LocalIdentity(bytes(1), bytes(2)))
        val oneTime = cipher.sealOneTimePreKey(OneTimePreKeyPair(OneTimePreKeyId(0), bytes(1), bytes(2)))
        assertEquals(identity.size, oneTime.size)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openOneTimePreKey(OneTimePreKeyId(0), identity) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openIdentity(oneTime) }

        // Signed and one-time prekeys share the ID field; the record type separates them.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            cipher.openSignedPreKey(SignedPreKeyId(0), oneTime)
        }
        val session = cipher.sealSession(SecureSession(BOB, bytes(1, 40)))
        val pending = cipher.sealPendingFrame(BOB, m1, bytes(1, 40))
        assertEquals(session.size, pending.size)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openPendingFrame(BOB, m1, session) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openSession(BOB, pending) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.verifyKeyCheck(identity) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { cipher.openIdentity(cipher.sealKeyCheck()) }
    }

    @Test
    fun wrongKeyFailsForEveryRecordType() = runTest {
        val other = ClientRecordCipher(testKey(1, 100))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.openIdentity(cipher.sealIdentity(LocalIdentity(bytes(1), bytes(2)))) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.openSignedPreKey(SignedPreKeyId(1), cipher.sealSignedPreKey(signed(1))) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.openOneTimePreKey(OneTimePreKeyId(1), cipher.sealOneTimePreKey(oneTime(1))) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.openSession(BOB, cipher.sealSession(SecureSession(BOB, bytes(1)))) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.openPendingFrame(BOB, m1, cipher.sealPendingFrame(BOB, m1, bytes(1))) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { other.verifyKeyCheck(cipher.sealKeyCheck()) }
    }

    @Test
    fun corruptedRecordsFailForEveryType() = runTest {
        val records: List<Pair<ByteArray, suspend (ByteArray) -> Any>> = listOf(
            cipher.sealIdentity(LocalIdentity(bytes(1), bytes(2))) to { r -> cipher.openIdentity(r) },
            cipher.sealSignedPreKey(signed(1)) to { r -> cipher.openSignedPreKey(SignedPreKeyId(1), r) },
            cipher.sealOneTimePreKey(oneTime(1)) to { r -> cipher.openOneTimePreKey(OneTimePreKeyId(1), r) },
            cipher.sealSession(SecureSession(BOB, bytes(1))) to { r -> cipher.openSession(BOB, r) },
            cipher.sealPendingFrame(BOB, m1, bytes(1)) to { r -> cipher.openPendingFrame(BOB, m1, r) },
        )
        for ((record, open) in records) {
            for (index in listOf(10, 21, 22, record.size - 17, record.size - 1)) {
                assertFailsWith<StorageEncryptionException.AuthenticationFailed> { open(record.flipped(index)) }
            }
            assertFailsWith<StorageEncryptionException.UnsupportedFormat> { open(record.copyOf().also { it[4] = 9 }) }
            assertFailsWith<StorageEncryptionException.UnsupportedFormat> { open(record.copyOf().also { it[5] = 9 }) }
            assertFailsWith<StorageEncryptionException.KeyUnavailable> { open(record.flipped(9)) }
            assertFailsWith<StorageEncryptionException.MalformedRecord> { open(record.copyOf(20)) }
            assertFailsWith<StorageEncryptionException.AuthenticationFailed> { open(record.copyOf(record.size - 1)) }
        }
    }

    @Test
    fun keyWrapperAndProvider() = runTest {
        assertFailsWith<IllegalArgumentException> { StorageEncryptionKey(StorageKeyId(1), ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { StorageKeyId(-1) }
        val source = ByteArray(32) { 0x42 }
        val key = StorageEncryptionKey(StorageKeyId(3), source)
        source.fill(0)
        assertContentEquals(ByteArray(32) { 0x42 }, key.copyBytes())
        key.copyBytes().fill(0)
        assertContentEquals(ByteArray(32) { 0x42 }, key.copyBytes())
        assertFalse(key.toString().contains("42"))
        assertTrue(key.toString().contains("redacted"))

        val generated = StorageEncryptionKey.generate(StorageKeyId(1))
        assertFalse(generated.copyBytes().contentEquals(StorageEncryptionKey.generate(StorageKeyId(1)).copyBytes()))

        val provider = StaticStorageKeyProvider(key, testKey(4, 0))
        assertEquals(StorageKeyId(3), provider.loadOrCreateKey().id)
        assertEquals(StorageKeyId(4), provider.key(StorageKeyId(4))?.id)
        assertEquals(null, provider.key(StorageKeyId(5)))
        assertFailsWith<IllegalArgumentException> { StaticStorageKeyProvider(key, testKey(3, 1)) }
    }
}
