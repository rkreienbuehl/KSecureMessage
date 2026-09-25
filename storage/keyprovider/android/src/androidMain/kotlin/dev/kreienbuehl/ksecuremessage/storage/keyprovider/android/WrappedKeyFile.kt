package dev.kreienbuehl.ksecuremessage.storage.keyprovider.android

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId

/** The wrapped key file cannot be parsed. Never carries file contents. */
internal class MalformedWrappedKeyFile(message: String) : Exception(message)

/**
 * Contents of the wrapped key file, format version 1
 * (docs/storage-key-providers.md). Big-endian:
 *
 * ```
 * magic "KSKW" | version u8 = 1 | alias length u16 | alias UTF-8
 * | current key ID i32 | entry count u16 (>= 1)
 * | entries: key ID i32 | IV length u8 = 12 | IV | ciphertext length u16 = 48 | ciphertext + tag
 * ```
 *
 * Each entry is a storage key wrapped with AES-GCM under the Keystore key
 * [alias]. Entries are sorted by key ID; [currentKeyId] names one of them.
 * Only milestone 10 writes a single entry; more are for key rotation.
 */
internal class WrappedKeyFile(val alias: String, val currentKeyId: StorageKeyId, val entries: List<Entry>) {
    class Entry(val keyId: StorageKeyId, iv: ByteArray, ciphertext: ByteArray) {
        val iv: ByteArray = iv.copyOf()
        val ciphertext: ByteArray = ciphertext.copyOf()

        init {
            require(this.iv.size == IV_SIZE) { "Invalid IV size" }
            require(this.ciphertext.size == CIPHERTEXT_SIZE) { "Invalid wrapped key size" }
        }
    }

    init {
        require(alias.isNotEmpty() && alias.encodeToByteArray().size <= 0xFFFF) { "Invalid alias" }
        require(entries.isNotEmpty() && entries.size <= 0xFFFF) { "Invalid entry count" }
        require(entries.map { it.keyId }.toSet().size == entries.size) { "Duplicate key ID" }
        require(entries.any { it.keyId == currentKeyId }) { "Current key ID has no entry" }
    }

    fun entry(id: StorageKeyId): Entry? = entries.firstOrNull { it.keyId == id }

    fun encode(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val data = java.io.DataOutputStream(out)
        data.write(MAGIC)
        data.writeByte(VERSION)
        val aliasBytes = alias.encodeToByteArray()
        data.writeShort(aliasBytes.size)
        data.write(aliasBytes)
        data.writeInt(currentKeyId.value)
        data.writeShort(entries.size)
        entries.sortedBy { it.keyId.value }.forEach { entry ->
            data.writeInt(entry.keyId.value)
            data.writeByte(entry.iv.size)
            data.write(entry.iv)
            data.writeShort(entry.ciphertext.size)
            data.write(entry.ciphertext)
        }
        data.flush()
        return out.toByteArray()
    }

    companion object {
        const val VERSION: Int = 1
        const val IV_SIZE: Int = 12
        const val TAG_SIZE: Int = 16
        const val CIPHERTEXT_SIZE: Int = StorageEncryptionKey.SIZE + TAG_SIZE
        private val MAGIC = "KSKW".encodeToByteArray()

        fun decode(bytes: ByteArray): WrappedKeyFile {
            val reader = Reader(bytes)
            if (!reader.bytes(MAGIC.size).contentEquals(MAGIC)) throw MalformedWrappedKeyFile("Not a wrapped storage key file")
            val version = reader.u8()
            if (version != VERSION) throw MalformedWrappedKeyFile("Unsupported wrapped storage key file version $version")
            val alias = try {
                reader.bytes(reader.u16()).decodeToString(throwOnInvalidSequence = true)
            } catch (_: CharacterCodingException) {
                throw MalformedWrappedKeyFile("Invalid Keystore alias")
            }
            val current = reader.keyId()
            val count = reader.u16()
            if (count == 0) throw MalformedWrappedKeyFile("Wrapped storage key file has no key")
            var previous = -1
            val entries = List(count) {
                val id = reader.keyId()
                if (id.value <= previous) throw MalformedWrappedKeyFile("Wrapped storage key entries are not sorted or not unique")
                previous = id.value
                val ivSize = reader.u8()
                if (ivSize != IV_SIZE) throw MalformedWrappedKeyFile("Invalid wrapped storage key IV size")
                val iv = reader.bytes(ivSize)
                val ciphertextSize = reader.u16()
                if (ciphertextSize != CIPHERTEXT_SIZE) throw MalformedWrappedKeyFile("Invalid wrapped storage key size")
                Entry(id, iv, reader.bytes(ciphertextSize))
            }
            if (!reader.atEnd) throw MalformedWrappedKeyFile("Trailing bytes in wrapped storage key file")
            if (alias.isEmpty()) throw MalformedWrappedKeyFile("Empty Keystore alias")
            if (entries.none { it.keyId == current }) throw MalformedWrappedKeyFile("Current storage key has no entry")
            return WrappedKeyFile(alias, current, entries)
        }
    }

    private class Reader(private val bytes: ByteArray) {
        private var position = 0

        val atEnd: Boolean get() = position == bytes.size

        fun bytes(count: Int): ByteArray {
            if (count > bytes.size - position) throw MalformedWrappedKeyFile("Truncated wrapped storage key file")
            return bytes.copyOfRange(position, position + count).also { position += count }
        }

        fun u8(): Int = bytes(1)[0].toInt() and 0xFF

        fun u16(): Int = (u8() shl 8) or u8()

        fun keyId(): StorageKeyId {
            val value = (u16() shl 16) or u16()
            if (value < 0) throw MalformedWrappedKeyFile("Invalid storage key ID")
            return StorageKeyId(value)
        }
    }
}
