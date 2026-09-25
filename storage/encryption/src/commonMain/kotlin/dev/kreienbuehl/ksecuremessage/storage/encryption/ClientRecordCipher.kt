package dev.kreienbuehl.ksecuremessage.storage.encryption

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.protocol.LocalIdentity
import dev.kreienbuehl.ksecuremessage.protocol.OneTimePreKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.SecureSession
import dev.kreienbuehl.ksecuremessage.protocol.SignedPreKeyPair

/**
 * Seals and opens the sensitive client storage records with one storage key
 * (docs/storage-encryption.md). Storage adapters store the sealed bytes as
 * they are; they never handle keys, formats or associated data themselves.
 *
 * Every sealed record is bound to its record type and to the row key given
 * here: a record opened as another type or under another key fails with
 * [StorageEncryptionException.AuthenticationFailed]. Opening never returns a
 * partial or default value; every failure throws a
 * [StorageEncryptionException].
 */
interface ClientRecordCipher {
    /** The key this cipher seals with (the current storage key). */
    val keyId: StorageKeyId

    /**
     * The keys this cipher opens records of: [keyId] and, during a storage key
     * rotation, the retained previous key (docs/storage-key-rotation.md).
     */
    val openableKeyIds: Set<StorageKeyId>

    /** The whole identity key pair. */
    suspend fun sealIdentity(identity: LocalIdentity): ByteArray
    suspend fun openIdentity(sealed: ByteArray): LocalIdentity

    /** Public key, signature and private key, bound to the prekey ID. */
    suspend fun sealSignedPreKey(preKey: SignedPreKeyPair): ByteArray
    suspend fun openSignedPreKey(id: SignedPreKeyId, sealed: ByteArray): SignedPreKeyPair

    /** Public and private key, bound to the prekey ID. */
    suspend fun sealOneTimePreKey(preKey: OneTimePreKeyPair): ByteArray
    suspend fun openOneTimePreKey(id: OneTimePreKeyId, sealed: ByteArray): OneTimePreKeyPair

    /** The session state, bound to the remote address. */
    suspend fun sealSession(session: SecureSession): ByteArray
    suspend fun openSession(remote: DeviceAddress, sealed: ByteArray): SecureSession

    /** A pending message frame, bound to the recipient and the logical message ID. */
    suspend fun sealPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): ByteArray
    suspend fun openPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, sealed: ByteArray): ByteArray

    /** A record with no content that proves the key when opened. */
    suspend fun sealKeyCheck(): ByteArray

    /** Throws [StorageEncryptionException] unless [sealed] is a key check sealed with this key. */
    suspend fun verifyKeyCheck(sealed: ByteArray)
}

/**
 * The AES-256-GCM [ClientRecordCipher] that seals with [current] and opens
 * records of [current] and of every [retained] key, chosen by the key ID in
 * each record. Retained keys are for storage key rotation only.
 */
fun ClientRecordCipher(current: StorageEncryptionKey, vararg retained: StorageEncryptionKey): ClientRecordCipher =
    AeadClientRecordCipher(StorageCipher(current, retained.toList()))

/**
 * Reads the header of a sealed storage record without decrypting it, for
 * storage key rotation (docs/storage-key-rotation.md). Only the format
 * module knows the record layout; storage adapters use this instead.
 */
object SealedRecords {
    /** Size of the record header that [header] returns. */
    const val HEADER_SIZE: Int = EncryptedRecordFormat.HEADER_SIZE

    /**
     * The ID of the key that sealed [record]. Checks magic, version,
     * algorithm and minimum size; throws [StorageEncryptionException]. Does
     * not authenticate the record.
     */
    fun keyId(record: ByteArray): StorageKeyId = EncryptedRecordFormat.parse(record).keyId

    /** The header every record sealed with key [keyId] starts with. */
    fun header(keyId: StorageKeyId): ByteArray = EncryptedRecordFormat.header(keyId)
}

/**
 * Record plaintext encodings, version 1. Local storage format, not wire
 * format:
 *
 * - identity: `version:u8 = 1 | bytes(publicKey) | bytes(privateKey)`
 * - signed prekey: `version:u8 = 1 | bytes(publicKey) | bytes(signature) | bytes(privateKey)`
 * - one-time prekey: `version:u8 = 1 | bytes(publicKey) | bytes(privateKey)`
 * - session: the session state as is (it has its own version)
 * - pending frame: the frame as is (SecurePayload has its own version)
 * - key check: empty
 *
 * `bytes(x)` is a u32 big-endian length followed by x. IDs and addresses are
 * not in the plaintext; they are bound through the associated data.
 */
internal class AeadClientRecordCipher(private val cipher: StorageCipher) : ClientRecordCipher {
    override val keyId: StorageKeyId get() = cipher.keyId

    override val openableKeyIds: Set<StorageKeyId> get() = cipher.openableKeyIds

    override suspend fun sealIdentity(identity: LocalIdentity): ByteArray =
        sealEncoded(StorageRecordType.LOCAL_IDENTITY, emptyList()) {
            bytes(identity.publicKey)
            bytes(identity.privateKey)
        }

    override suspend fun openIdentity(sealed: ByteArray): LocalIdentity =
        openEncoded(StorageRecordType.LOCAL_IDENTITY, emptyList(), sealed) { LocalIdentity(bytes(), bytes()) }

    override suspend fun sealSignedPreKey(preKey: SignedPreKeyPair): ByteArray =
        sealEncoded(StorageRecordType.SIGNED_PRE_KEY, listOf(intBytes(preKey.id.value))) {
            bytes(preKey.publicKey)
            bytes(preKey.signature)
            bytes(preKey.privateKey)
        }

    override suspend fun openSignedPreKey(id: SignedPreKeyId, sealed: ByteArray): SignedPreKeyPair =
        openEncoded(StorageRecordType.SIGNED_PRE_KEY, listOf(intBytes(id.value)), sealed) {
            SignedPreKeyPair(id, bytes(), bytes(), bytes())
        }

    override suspend fun sealOneTimePreKey(preKey: OneTimePreKeyPair): ByteArray =
        sealEncoded(StorageRecordType.ONE_TIME_PRE_KEY, listOf(intBytes(preKey.id.value))) {
            bytes(preKey.publicKey)
            bytes(preKey.privateKey)
        }

    override suspend fun openOneTimePreKey(id: OneTimePreKeyId, sealed: ByteArray): OneTimePreKeyPair =
        openEncoded(StorageRecordType.ONE_TIME_PRE_KEY, listOf(intBytes(id.value)), sealed) {
            OneTimePreKeyPair(id, bytes(), bytes())
        }

    override suspend fun sealSession(session: SecureSession): ByteArray =
        cipher.seal(StorageRecordType.SESSION, session.remote.fields(), session.state)

    override suspend fun openSession(remote: DeviceAddress, sealed: ByteArray): SecureSession =
        SecureSession(remote, cipher.open(StorageRecordType.SESSION, remote.fields(), sealed))

    override suspend fun sealPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, frame: ByteArray): ByteArray =
        cipher.seal(StorageRecordType.PENDING_OUTBOUND, recipient.fields() + id.toByteArray(), frame)

    override suspend fun openPendingFrame(recipient: DeviceAddress, id: LogicalMessageId, sealed: ByteArray): ByteArray =
        cipher.open(StorageRecordType.PENDING_OUTBOUND, recipient.fields() + id.toByteArray(), sealed)

    override suspend fun sealKeyCheck(): ByteArray = cipher.seal(StorageRecordType.KEY_CHECK, emptyList(), ByteArray(0))

    override suspend fun verifyKeyCheck(sealed: ByteArray) {
        val content = cipher.open(StorageRecordType.KEY_CHECK, emptyList(), sealed)
        if (content.isNotEmpty()) throw StorageEncryptionException.MalformedRecord("Invalid key check record")
    }

    private suspend fun sealEncoded(type: StorageRecordType, fields: List<ByteArray>, encode: RecordWriter.() -> Unit): ByteArray {
        val plaintext = RecordWriter().apply { byte(RECORD_VERSION) }.apply(encode).toByteArray()
        return try {
            cipher.seal(type, fields, plaintext)
        } finally {
            plaintext.fill(0) // best effort
        }
    }

    private suspend fun <T> openEncoded(
        type: StorageRecordType,
        fields: List<ByteArray>,
        sealed: ByteArray,
        decode: RecordReader.() -> T,
    ): T {
        val plaintext = cipher.open(type, fields, sealed)
        try {
            val reader = RecordReader(plaintext)
            val version = reader.byte()
            if (version != RECORD_VERSION) {
                throw StorageEncryptionException.UnsupportedFormat("Unsupported ${type.name} record version $version")
            }
            return reader.decode().also { reader.requireEnd() }
        } finally {
            plaintext.fill(0) // best effort
        }
    }

    private fun DeviceAddress.fields(): List<ByteArray> =
        listOf(userId.value.encodeToByteArray(), deviceId.value.encodeToByteArray())

    private companion object {
        const val RECORD_VERSION: Byte = 1
    }
}
