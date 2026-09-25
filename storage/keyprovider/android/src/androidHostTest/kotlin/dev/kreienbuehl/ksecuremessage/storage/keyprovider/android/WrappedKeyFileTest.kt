package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class WrappedKeyFileTest {
    private val alias = "dev.kreienbuehl.ksecuremessage.storage.v1.default"

    private fun entry(id: Int, seed: Int) = WrappedKeyFile.Entry(StorageKeyId(id), ByteArray(12) { (seed + it).toByte() }, ByteArray(48) { (seed * 3 + it).toByte() })

    private fun sample() = WrappedKeyFile(alias, StorageKeyId(1), listOf(entry(1, 1))).encode()

    @Test
    fun roundTrip() {
        val file = WrappedKeyFile(alias, StorageKeyId(2), listOf(entry(2, 5), entry(1, 9)))
        val decoded = WrappedKeyFile.decode(file.encode())
        assertEquals(alias, decoded.alias)
        assertEquals(StorageKeyId(2), decoded.currentKeyId)
        assertEquals(listOf(1, 2), decoded.entries.map { it.keyId.value })
        assertContentEquals(entry(2, 5).iv, decoded.entry(StorageKeyId(2))!!.iv)
        assertContentEquals(entry(1, 9).ciphertext, decoded.entry(StorageKeyId(1))!!.ciphertext)
    }

    @Test
    fun layoutIsVersion1() {
        val bytes = sample()
        assertContentEquals("KSKW".encodeToByteArray(), bytes.copyOfRange(0, 4))
        assertEquals(1, bytes[4].toInt())
        // magic, version, alias, current ID, count, one entry
        assertEquals(4 + 1 + 2 + alias.length + 4 + 2 + (4 + 1 + 12 + 2 + 48), bytes.size)
    }

    @Test
    fun rejectsDamagedFiles() {
        val bytes = sample()
        val aliasEnd = 7 + alias.length
        val damaged = listOf(
            ByteArray(0),
            bytes.copyOf(3),
            bytes.copyOf().also { it[0] = 'X'.code.toByte() },
            bytes.copyOf().also { it[4] = 2 },
            bytes.copyOf(bytes.size - 1),
            bytes + 0,
            bytes.copyOf().also { it[5] = 0; it[6] = 0 }, // empty alias, structure shifted
            bytes.copyOf().also { it[aliasEnd + 3] = 9 }, // current ID without entry
            bytes.copyOf().also { it[aliasEnd + 4] = 0; it[aliasEnd + 5] = 0 }, // no entries
            bytes.copyOf().also { it[aliasEnd + 10] = 16 }, // IV size
            bytes.copyOf().also { it[aliasEnd + 24] = 47 }, // ciphertext size
            bytes.copyOf().also { it[aliasEnd] = 0x80.toByte() }, // negative current ID
        )
        damaged.forEach { assertFailsWith<MalformedWrappedKeyFile> { WrappedKeyFile.decode(it) } }
    }

    @Test
    fun rejectsDuplicateOrUnsortedEntries() {
        val two = WrappedKeyFile(alias, StorageKeyId(1), listOf(entry(1, 1), entry(2, 2))).encode()
        val aliasEnd = 7 + alias.length
        val firstId = aliasEnd + 6
        val secondId = firstId + 4 + 1 + 12 + 2 + 48
        assertFailsWith<MalformedWrappedKeyFile> { WrappedKeyFile.decode(two.copyOf().also { it[secondId + 3] = 1 }) }
        assertFailsWith<MalformedWrappedKeyFile> { WrappedKeyFile.decode(two.copyOf().also { it[firstId + 3] = 3 }) }
        assertFailsWith<IllegalArgumentException> { WrappedKeyFile(alias, StorageKeyId(1), listOf(entry(1, 1), entry(1, 2))) }
    }
}
