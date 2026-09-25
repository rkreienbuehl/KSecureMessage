package dev.kreienbuehl.ksecuremessage.storage.encryption

/**
 * Record types of the canonical associated data. The IDs are part of the
 * stored format and must never change or be reused.
 */
internal enum class StorageRecordType(val id: Byte) {
    LOCAL_IDENTITY(1),
    SIGNED_PRE_KEY(2),
    ONE_TIME_PRE_KEY(3),
    SESSION(4),
    PENDING_OUTBOUND(5),
    KEY_CHECK(6),
}

/**
 * Encrypted storage record, format version 1 (docs/storage-encryption.md).
 * Local persistence only; unrelated to the wire format and its versions.
 *
 * ```
 * magic "KSMR" (4) | version:u8 = 1 | algorithm:u8 = 1 | keyId:u32
 * | nonce (12) | ciphertext || tag (16)
 * ```
 *
 * Algorithm 1 is AES-256-GCM with a 96-bit random nonce and a 128-bit tag.
 * The 10-byte header is part of the associated data, so it is authenticated.
 */
internal object EncryptedRecordFormat {
    private val MAGIC = byteArrayOf(0x4B, 0x53, 0x4D, 0x52)
    const val VERSION: Byte = 1
    const val ALGORITHM_AES_256_GCM: Byte = 1
    const val HEADER_SIZE: Int = 10
    const val MIN_SIZE: Int = HEADER_SIZE + AesGcm.NONCE_SIZE + AesGcm.TAG_SIZE

    /** Domain of the associated data; never change it. */
    const val DOMAIN: String = "KSecureMessage-Storage-v1"

    class Parsed(val header: ByteArray, val keyId: StorageKeyId, val nonce: ByteArray, val ciphertext: ByteArray)

    fun header(keyId: StorageKeyId): ByteArray =
        MAGIC + byteArrayOf(VERSION, ALGORITHM_AES_256_GCM) + intBytes(keyId.value)

    /** Checks magic, version and algorithm before anything else. Throws [StorageEncryptionException]. */
    fun parse(record: ByteArray): Parsed {
        if (record.size < MAGIC.size) throw StorageEncryptionException.MalformedRecord("Truncated storage record")
        if (!record.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            throw StorageEncryptionException.UnsupportedFormat("Not an encrypted storage record")
        }
        if (record.size < MAGIC.size + 2) throw StorageEncryptionException.MalformedRecord("Truncated storage record")
        if (record[4] != VERSION) throw StorageEncryptionException.UnsupportedFormat("Unsupported storage record version ${record[4]}")
        if (record[5] != ALGORITHM_AES_256_GCM) {
            throw StorageEncryptionException.UnsupportedFormat("Unsupported storage record algorithm ${record[5]}")
        }
        if (record.size < MIN_SIZE) throw StorageEncryptionException.MalformedRecord("Truncated storage record")
        val reader = RecordReader(record)
        val header = reader.fixed(HEADER_SIZE)
        val keyIdValue = RecordReader(header.copyOfRange(6, 10)).int()
        if (keyIdValue < 0) throw StorageEncryptionException.MalformedRecord("Invalid storage key ID")
        val nonce = reader.fixed(AesGcm.NONCE_SIZE)
        val ciphertext = reader.fixed(record.size - HEADER_SIZE - AesGcm.NONCE_SIZE)
        return Parsed(header, StorageKeyId(keyIdValue), nonce, ciphertext)
    }

    /**
     * Canonical associated data:
     *
     * ```
     * header (10) | u32 length | DOMAIN (UTF-8) | recordType:u8 | fieldCount:u8
     * | (u32 length | field)*
     * ```
     *
     * Every variable field is length-prefixed, so different field lists never
     * encode to the same bytes.
     */
    fun associatedData(header: ByteArray, type: StorageRecordType, fields: List<ByteArray>): ByteArray {
        require(header.size == HEADER_SIZE)
        require(fields.size <= 255)
        val out = RecordWriter()
        out.fixed(header)
        out.bytes(DOMAIN.encodeToByteArray())
        out.byte(type.id)
        out.byte(fields.size.toByte())
        fields.forEach { out.bytes(it) }
        return out.toByteArray()
    }
}

/**
 * Seals and opens records with one storage key. Knows nothing about record
 * contents; [ClientRecordCipher] does.
 */
internal class StorageCipher(
    private val key: StorageEncryptionKey,
    // Replaced only by fixed-vector tests. Production nonces are random.
    private val nonces: () -> ByteArray = { secureRandomBytes(AesGcm.NONCE_SIZE) },
) {
    val keyId: StorageKeyId get() = key.id

    suspend fun seal(type: StorageRecordType, fields: List<ByteArray>, plaintext: ByteArray): ByteArray {
        val header = EncryptedRecordFormat.header(key.id)
        val nonce = nonces()
        check(nonce.size == AesGcm.NONCE_SIZE) { "Invalid nonce" }
        val keyBytes = key.copyBytes()
        val ciphertext = try {
            AesGcm.encrypt(keyBytes, nonce, plaintext, EncryptedRecordFormat.associatedData(header, type, fields))
        } finally {
            keyBytes.fill(0)
        }
        return header + nonce + ciphertext
    }

    suspend fun open(type: StorageRecordType, fields: List<ByteArray>, record: ByteArray): ByteArray {
        val parsed = EncryptedRecordFormat.parse(record)
        if (parsed.keyId != key.id) {
            throw StorageEncryptionException.KeyUnavailable("Record uses storage key ${parsed.keyId.value}, which this storage does not use")
        }
        val keyBytes = key.copyBytes()
        val plaintext = try {
            AesGcm.decrypt(keyBytes, parsed.nonce, parsed.ciphertext, EncryptedRecordFormat.associatedData(parsed.header, type, fields))
        } finally {
            keyBytes.fill(0)
        }
        return plaintext ?: throw StorageEncryptionException.AuthenticationFailed("Storage record failed authentication")
    }
}
