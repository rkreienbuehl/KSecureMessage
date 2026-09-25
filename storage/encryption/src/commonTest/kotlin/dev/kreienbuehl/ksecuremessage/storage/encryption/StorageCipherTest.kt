package dev.kreienbuehl.ksecuremessage.storage.encryption

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class StorageCipherTest {
    private val key = StorageEncryptionKey(StorageKeyId(7), ByteArray(32) { it.toByte() })
    private val fields = listOf("bob".encodeToByteArray(), "laptop".encodeToByteArray())
    private val plaintext = "ratchet-state".encodeToByteArray()

    // Computed independently (Python `cryptography`, AESGCM). Frozen: a change
    // here is a change of the stored format.
    private val vectorAssociatedData =
        "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d7631040200000003626f62000000066c6170746f70"
    private val vectorRecord =
        "4b534d52010100000007a0a1a2a3a4a5a6a7a8a9aaab9479084e2dae76921111e6a762f6e5f769cd5531b252c0472a9e5067b2"

    private fun fixedNonceCipher() = StorageCipher(key) { ByteArray(12) { (0xA0 + it).toByte() } }

    private val cipher = StorageCipher(key)

    @Test
    fun fixedVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(vectorAssociatedData, EncryptedRecordFormat.associatedData(header, StorageRecordType.SESSION, fields).toHex())
        assertEquals(vectorRecord, fixedNonceCipher().seal(StorageRecordType.SESSION, fields, plaintext).toHex())
        assertContentEquals(plaintext, cipher.open(StorageRecordType.SESSION, fields, hex(vectorRecord)))
    }

    @Test
    fun roundtripAndLayout() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        assertEquals(10 + 12 + plaintext.size + 16, record.size)
        assertEquals("4b534d5201010000000" + "7", record.copyOfRange(0, 10).toHex())
        assertContentEquals(plaintext, cipher.open(StorageRecordType.SESSION, fields, record))
        assertContentEquals(ByteArray(0), cipher.open(StorageRecordType.KEY_CHECK, emptyList(), cipher.seal(StorageRecordType.KEY_CHECK, emptyList(), ByteArray(0))))
    }

    @Test
    fun samePlaintextGivesDifferentRecords() = runTest {
        val first = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        val second = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        assertFalse(first.contentEquals(second))
        assertFalse(first.copyOfRange(10, 22).contentEquals(second.copyOfRange(10, 22)), "nonces must differ")
        assertContentEquals(plaintext, cipher.open(StorageRecordType.SESSION, fields, first))
        assertContentEquals(plaintext, cipher.open(StorageRecordType.SESSION, fields, second))
    }

    @Test
    fun wrongKeyFails() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        val sameIdOtherBytes = StorageCipher(StorageEncryptionKey(StorageKeyId(7), ByteArray(32) { 9 }))
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { sameIdOtherBytes.open(StorageRecordType.SESSION, fields, record) }
    }

    @Test
    fun unknownKeyIdIsKeyUnavailable() = runTest {
        val record = StorageCipher(testKey(8, 0)).seal(StorageRecordType.SESSION, fields, plaintext)
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { cipher.open(StorageRecordType.SESSION, fields, record) }
    }

    @Test
    fun wrongAssociatedDataFails() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            cipher.open(StorageRecordType.SESSION, listOf("bob".encodeToByteArray(), "phone".encodeToByteArray()), record)
        }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            cipher.open(StorageRecordType.PENDING_OUTBOUND, fields, record)
        }
    }

    @Test
    fun bitFlipsFail() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        val nonce = 10
        val ciphertext = 22
        val tag = record.size - 1
        for (index in listOf(nonce, nonce + 11, ciphertext, ciphertext + plaintext.size - 1, record.size - 16, tag)) {
            assertFailsWith<StorageEncryptionException.AuthenticationFailed>("byte $index") {
                cipher.open(StorageRecordType.SESSION, fields, record.flipped(index))
            }
        }
        // The key ID is in the header: another ID is an unknown key, never another key tried.
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { cipher.open(StorageRecordType.SESSION, fields, record.flipped(9)) }
    }

    @Test
    fun headerIsAuthenticated() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        val otherHeaderKey = StorageCipher(StorageEncryptionKey(StorageKeyId(6), ByteArray(32) { it.toByte() }))
        // Same key bytes, other ID: the header (with the ID) is part of the AD.
        val relabeled = record.copyOf().also { it[9] = 6 }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { otherHeaderKey.open(StorageRecordType.SESSION, fields, relabeled) }
    }

    @Test
    fun malformedAndUnsupportedRecords() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> { cipher.open(StorageRecordType.SESSION, fields, record.flipped(0)) }
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> { cipher.open(StorageRecordType.SESSION, fields, plaintext) }
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> {
            cipher.open(StorageRecordType.SESSION, fields, record.copyOf().also { it[4] = 2 })
        }
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> {
            cipher.open(StorageRecordType.SESSION, fields, record.copyOf().also { it[5] = 2 })
        }
        assertFailsWith<StorageEncryptionException.MalformedRecord> { cipher.open(StorageRecordType.SESSION, fields, ByteArray(0)) }
        assertFailsWith<StorageEncryptionException.MalformedRecord> { cipher.open(StorageRecordType.SESSION, fields, record.copyOf(5)) }
        // Truncated header, nonce, tag.
        for (size in listOf(9, 10, 21, 22, 37)) {
            assertFailsWith<StorageEncryptionException.MalformedRecord>("size $size") {
                cipher.open(StorageRecordType.SESSION, fields, record.copyOf(size))
            }
        }
        // Truncated ciphertext or tag that still has the minimum size.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            cipher.open(StorageRecordType.SESSION, fields, record.copyOf(record.size - 1))
        }
    }

    @Test
    fun associatedDataIsCanonical() {
        val header = EncryptedRecordFormat.header(StorageKeyId(1))
        fun ad(type: StorageRecordType, vararg fields: String) =
            EncryptedRecordFormat.associatedData(header, type, fields.map { it.encodeToByteArray() }).toHex()
        val all = listOf(
            ad(StorageRecordType.SESSION, "ab", "c"),
            ad(StorageRecordType.SESSION, "a", "bc"),
            ad(StorageRecordType.SESSION, "abc"),
            ad(StorageRecordType.SESSION, "abc", ""),
            ad(StorageRecordType.PENDING_OUTBOUND, "ab", "c"),
            ad(StorageRecordType.LOCAL_IDENTITY),
            ad(StorageRecordType.KEY_CHECK),
            EncryptedRecordFormat.associatedData(EncryptedRecordFormat.header(StorageKeyId(2)), StorageRecordType.KEY_CHECK, emptyList()).toHex(),
        )
        assertEquals(all.size, all.toSet().size)
        assertEquals(listOf<Byte>(1, 2, 3, 4, 5, 6), StorageRecordType.entries.map { it.id })
    }
}
