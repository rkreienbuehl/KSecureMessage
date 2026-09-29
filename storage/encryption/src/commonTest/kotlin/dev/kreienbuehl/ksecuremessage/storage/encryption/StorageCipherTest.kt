package dev.kreienbuehl.ksecuremessage.storage.encryption

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.LogicalMessageId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
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

    /**
     * Record type 7 (milestone 12): the device authentication key pair,
     * `version:u8 = 1 | bytes(publicKey) | bytes(privateKey)`, no row fields.
     * Computed independently (Python `cryptography`, AESGCM). Frozen.
     */
    @Test
    fun deviceAuthenticationKeyVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310700",
            EncryptedRecordFormat.associatedData(header, StorageRecordType.DEVICE_AUTHENTICATION_KEY, emptyList()).toHex(),
        )
        val keyPair = DeviceAuthenticationKeyPair(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
        val vector = "4b534d52010100000007a0a1a2a3a4a5a6a7a8a9aaabe7187c2d65da13ae737496c2166bd1cf61bd480183a6537d8d1f37976eba6410c3" +
            "6756eebe22533d7fbe26ea2b58a1db6539646a40f2385c637c297c8652a792969ea74d1287c6c2d6175041e4e06246d3fdefb64732241fd7"
        assertEquals(vector, AeadClientRecordCipher(fixedNonceCipher()).sealDeviceAuthenticationKey(keyPair).toHex())
        val opened = ClientRecordCipher(key).openDeviceAuthenticationKey(hex(vector))
        assertContentEquals(keyPair.publicKey, opened.publicKey)
        assertContentEquals(keyPair.privateKey, opened.privateKey)
    }

    /**
     * Record type 8 (milestone 14): the pending replacement key pair of a
     * device recovery, same content layout as type 7. Computed independently
     * (Python `cryptography`, AESGCM). Frozen.
     */
    @Test
    fun deviceAuthenticationRecoveryKeyVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310800",
            EncryptedRecordFormat.associatedData(header, StorageRecordType.DEVICE_AUTHENTICATION_RECOVERY_KEY, emptyList()).toHex(),
        )
        val keyPair = DeviceAuthenticationKeyPair(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
        val vector = "4b534d52010100000007a0a1a2a3a4a5a6a7a8a9aaabe7187c2d65da13ae737496c2166bd1cf61bd480183a6537d8d1f37976eba6410c3" +
            "6756eebe22533d7fbe26ea2b58a1db6539646a40f2385c637c297c8652a792969ea74d1287c6c2d600615bd9550843e343e823814af81b92"
        assertEquals(vector, AeadClientRecordCipher(fixedNonceCipher()).sealDeviceAuthenticationRecoveryKey(keyPair).toHex())
        val opened = ClientRecordCipher(key).openDeviceAuthenticationRecoveryKey(hex(vector))
        assertContentEquals(keyPair.publicKey, opened.publicKey)
        assertContentEquals(keyPair.privateKey, opened.privateKey)
        assertEquals(8, StorageRecordType.DEVICE_AUTHENTICATION_RECOVERY_KEY.id.toInt())
        assertEquals(7, StorageRecordType.DEVICE_AUTHENTICATION_KEY.id.toInt())
    }

    /**
     * Record type 9 (milestone 16): the pending replacement key pair of a
     * routine device authentication key rotation, same content layout as
     * types 7 and 8. Computed independently (Python `cryptography`, AESGCM;
     * the same script first reproduced the type 7 and 8 vectors). Frozen.
     * Its own fixed nonce: the JVM refuses to reuse a GCM nonce with the same
     * key in consecutive encryptions.
     */
    @Test
    fun deviceAuthenticationRotationKeyVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310900",
            EncryptedRecordFormat.associatedData(header, StorageRecordType.DEVICE_AUTHENTICATION_ROTATION_KEY, emptyList()).toHex(),
        )
        val keyPair = DeviceAuthenticationKeyPair(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
        val vector = "4b534d52010100000007b0b1b2b3b4b5b6b7b8b9babb98555aabccdcaa4e56e986b3dc4c99d3952d58c3043f9e244fdf93e04d93e307145a" +
            "322b72dea6b8857982681e9ba0970f4f35e5391960d26fa84e1226b902dd90ca1c96289e44f83b6e036706fe2757bb87b5b7661d8f79bd"
        val cipher = StorageCipher(key) { ByteArray(12) { (0xB0 + it).toByte() } }
        assertEquals(vector, AeadClientRecordCipher(cipher).sealDeviceAuthenticationRotationKey(keyPair).toHex())
        val opened = ClientRecordCipher(key).openDeviceAuthenticationRotationKey(hex(vector))
        assertContentEquals(keyPair.publicKey, opened.publicKey)
        assertContentEquals(keyPair.privateKey, opened.privateKey)
        assertEquals(9, StorageRecordType.DEVICE_AUTHENTICATION_ROTATION_KEY.id.toInt())
        assertEquals(StorageRecordType.entries.size, StorageRecordType.entries.map { it.id }.toSet().size)
    }

    /**
     * Record type 10 (milestone 18): the pending replacement key pair of a
     * last-device recovery, same content layout as types 7 to 9. Computed
     * independently (Python `cryptography`, AESGCM; the same script first
     * reproduced the type 9 vector). Frozen. Its own fixed nonce.
     */
    @Test
    fun deviceAuthenticationLastDeviceRecoveryKeyVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310a00",
            EncryptedRecordFormat.associatedData(header, StorageRecordType.DEVICE_AUTHENTICATION_LAST_DEVICE_RECOVERY_KEY, emptyList()).toHex(),
        )
        val keyPair = DeviceAuthenticationKeyPair(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 })
        val vector = "4b534d52010100000007c0c1c2c3c4c5c6c7c8c9cacb014827675769874f89c8ecb323bdf9475d62f22e2df30eab3bd25a1b266c6ea7ad8786" +
            "b663db4503e86f763bdbe647abaf47fd58f0ef823ba6070cf2c0c5193f2f0ea91fcbe45e8e40ad7b692ab1bc2b6ffe3be84a7d6658f1"
        val cipher = StorageCipher(key) { ByteArray(12) { (0xC0 + it).toByte() } }
        assertEquals(vector, AeadClientRecordCipher(cipher).sealDeviceAuthenticationLastDeviceRecoveryKey(keyPair).toHex())
        val opened = ClientRecordCipher(key).openDeviceAuthenticationLastDeviceRecoveryKey(hex(vector))
        assertContentEquals(keyPair.publicKey, opened.publicKey)
        assertContentEquals(keyPair.privateKey, opened.privateKey)
        assertEquals(10, StorageRecordType.DEVICE_AUTHENTICATION_LAST_DEVICE_RECOVERY_KEY.id.toInt())
        assertEquals(StorageRecordType.entries.size, StorageRecordType.entries.map { it.id }.toSet().size)
    }

    /**
     * Record type 11 (milestone 20): a received frame awaiting the
     * application's commit, bound to sender and logical message ID. The
     * plaintext is the SecurePayload frame as is. Computed independently
     * (Python `cryptography`, AESGCM). Frozen. Its own fixed nonce.
     */
    @Test
    fun pendingInboundFrameVector() = runTest {
        val sender = DeviceAddress(UserId("alice"), DeviceId("phone"))
        val id = LogicalMessageId.fromByteArray(ByteArray(16) { (0x10 + it).toByte() })
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310b0300000005616c6963650000000570686f6e65" +
                "00000010101112131415161718191a1b1c1d1e1f",
            EncryptedRecordFormat.associatedData(
                header,
                StorageRecordType.PENDING_INBOUND,
                listOf("alice".encodeToByteArray(), "phone".encodeToByteArray(), id.toByteArray()),
            ).toHex(),
        )
        val frame = byteArrayOf(1, 1) + id.toByteArray() + byteArrayOf(0, 0, 0, 5) + "hello".encodeToByteArray()
        val vector = "4b534d52010100000007d0d1d2d3d4d5d6d7d8d9dadb2da6f67f7ab4e5b44e4830a6eccd9bfcd1155dd54098d0235fe62178763f5af72c" +
            "5979e56a3c5e5a2d1c66"
        val cipher = StorageCipher(key) { ByteArray(12) { (0xD0 + it).toByte() } }
        assertEquals(vector, AeadClientRecordCipher(cipher).sealPendingInboundFrame(sender, id, frame).toHex())
        assertContentEquals(frame, ClientRecordCipher(key).openPendingInboundFrame(sender, id, hex(vector)))
        assertEquals(11, StorageRecordType.PENDING_INBOUND.id.toInt())
        assertEquals(StorageRecordType.entries.size, StorageRecordType.entries.map { it.id }.toSet().size)
    }

    /**
     * Record type 12 (milestone 20): the content digest of a committed
     * received message, `version:u8 = 1 | digest[32]`, bound to sender and
     * logical message ID. Computed independently (Python `cryptography`,
     * AESGCM). Frozen. Its own fixed nonce.
     */
    @Test
    fun processedDigestVector() = runTest {
        val sender = DeviceAddress(UserId("alice"), DeviceId("phone"))
        val id = LogicalMessageId.fromByteArray(ByteArray(16) { (0x10 + it).toByte() })
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310c0300000005616c6963650000000570686f6e65" +
                "00000010101112131415161718191a1b1c1d1e1f",
            EncryptedRecordFormat.associatedData(
                header,
                StorageRecordType.PROCESSED_INBOUND_DIGEST,
                listOf("alice".encodeToByteArray(), "phone".encodeToByteArray(), id.toByteArray()),
            ).toHex(),
        )
        val digest = ByteArray(32) { 0x33 }
        val vector = "4b534d52010100000007e0e1e2e3e4e5e6e7e8e9eaeb35f1fab0c6f3b918f3304d7d6d2fcbb0f69608d4cdb7fe2bafb2594e3f021bb9607e" +
            "5c95f2147bf079b9892b88ed18580b"
        val cipher = StorageCipher(key) { ByteArray(12) { (0xE0 + it).toByte() } }
        assertEquals(vector, AeadClientRecordCipher(cipher).sealProcessedDigest(sender, id, digest).toHex())
        assertContentEquals(digest, ClientRecordCipher(key).openProcessedDigest(sender, id, hex(vector)))
        assertEquals(12, StorageRecordType.PROCESSED_INBOUND_DIGEST.id.toInt())
    }

    /**
     * Record type 13 (S1, finding F7): the legacy plaintext migration intent,
     * row key field "legacy-plaintext-migration", content the fixed marker
     * "KSecureMessage-LegacyPlaintextMigration-v1". Computed independently
     * (Python `cryptography`, AESGCM). Frozen. Its own fixed nonce.
     */
    @Test
    fun migrationIntentVector() = runTest {
        val header = EncryptedRecordFormat.header(StorageKeyId(7))
        assertEquals(
            "4b534d52010100000007000000194b5365637572654d6573736167652d53746f726167652d76310d010000001a6c65676163792d706c61696e746578742d6d6967726174696f6e",
            EncryptedRecordFormat.associatedData(header, StorageRecordType.MIGRATION_INTENT, listOf("legacy-plaintext-migration".encodeToByteArray())).toHex(),
        )
        val vector = "4b534d52010100000007f0f1f2f3f4f5f6f7f8f9fafb225526630948b739fa8484fbe92f4ffa758638a1415723f93f3847c521479f6e7b6277f029ecdfb4ee69ccc4cfbb350ee55107466976b840ec7a"
        val cipher = StorageCipher(key) { ByteArray(12) { (0xF0 + it).toByte() } }
        assertEquals(vector, AeadClientRecordCipher(cipher).sealMigrationIntent().toHex())
        ClientRecordCipher(key).verifyMigrationIntent(hex(vector))
        assertEquals(13, StorageRecordType.MIGRATION_INTENT.id.toInt())
    }

    @Test
    fun migrationIntentIsNoKeyCheckAndNeedsItsKey() = runTest {
        val records = ClientRecordCipher(key)
        val intent = records.sealMigrationIntent()
        val keyCheck = records.sealKeyCheck()
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { records.verifyMigrationIntent(keyCheck) }
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> { records.verifyKeyCheck(intent) }
        assertFailsWith<StorageEncryptionException> { ClientRecordCipher(testKey(7, 99)).verifyMigrationIntent(intent) }
        assertFailsWith<StorageEncryptionException> { records.verifyMigrationIntent(intent.flipped(intent.size - 1)) }
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
    fun retainedKeyOpensItsRecordsAndSealingUsesTheCurrentKey() = runTest {
        val old = StorageCipher(testKey(1, 0))
        val oldRecord = old.seal(StorageRecordType.SESSION, fields, plaintext)
        val rotating = StorageCipher(testKey(2, 50), listOf(testKey(1, 0)))
        assertEquals(setOf(StorageKeyId(1), StorageKeyId(2)), rotating.openableKeyIds)

        assertContentEquals(plaintext, rotating.open(StorageRecordType.SESSION, fields, oldRecord))
        val resealed = rotating.seal(StorageRecordType.SESSION, fields, plaintext)
        assertEquals(StorageKeyId(2), SealedRecords.keyId(resealed))
        assertFalse(oldRecord.copyOfRange(10, 22).contentEquals(resealed.copyOfRange(10, 22)), "re-encryption uses a fresh nonce")
        assertContentEquals(plaintext, StorageCipher(testKey(2, 50)).open(StorageRecordType.SESSION, fields, resealed))
        // Same associated data after re-encryption: another row key still fails.
        assertFailsWith<StorageEncryptionException.AuthenticationFailed> {
            rotating.open(StorageRecordType.SESSION, listOf("bob".encodeToByteArray(), "phone".encodeToByteArray()), resealed)
        }
        // Once the old key is no longer retained, its records name an unavailable key.
        assertFailsWith<StorageEncryptionException.KeyUnavailable> { StorageCipher(testKey(2, 50)).open(StorageRecordType.SESSION, fields, oldRecord) }
        assertFailsWith<IllegalArgumentException> { StorageCipher(testKey(2, 50), listOf(testKey(2, 0))) }
    }

    @Test
    fun sealedRecordHeaderInspection() = runTest {
        val record = cipher.seal(StorageRecordType.SESSION, fields, plaintext)
        assertEquals(StorageKeyId(7), SealedRecords.keyId(record))
        assertContentEquals(record.copyOfRange(0, SealedRecords.HEADER_SIZE), SealedRecords.header(StorageKeyId(7)))
        assertFailsWith<StorageEncryptionException.UnsupportedFormat> { SealedRecords.keyId(plaintext) }
        assertFailsWith<StorageEncryptionException.MalformedRecord> { SealedRecords.keyId(record.copyOf(20)) }
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
        assertEquals(listOf<Byte>(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13), StorageRecordType.entries.map { it.id })
    }
}
