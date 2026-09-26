package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Instant

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * Frozen vectors of routine device authentication rotation format version 1
 * (docs/device-authentication-rotation.md). Every rotation a server accepted
 * depends on them. Computed independently (Python struct, hashlib and the
 * `cryptography` package's Ed25519) from the documented layout; the same
 * script first reproduced the frozen device recovery vectors.
 */
class DeviceAuthenticationRotationTest {
    private fun keyPair(first: Int, publicKey: String) =
        DeviceAuthenticationKeyPair(hex(publicKey), ByteArray(32) { (first + it).toByte() })

    private val key1 = keyPair(0x40, "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")
    private val key2 = keyPair(0x60, "174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5")
    private val key3 = keyPair(0x80, "cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa")
    private val key4 = keyPair(0xA0, "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4")

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val encoded = DeviceAddress(UserId("ä b/c"), DeviceId("dev~1"))
    private val timestamp = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val nonce1 = RequestNonce(ByteArray(16) { it.toByte() })
    private val nonce3 = RequestNonce(ByteArray(16) { (0xFF - it).toByte() })

    private class Case(
        val address: DeviceAddress,
        val current: DeviceAuthenticationKeyPair,
        val replacement: DeviceAuthenticationKeyPair,
        val epoch: Long,
        val timestamp: Instant,
        val nonce: RequestNonce,
    ) {
        fun authorization() = DeviceAuthenticationRotation.create(current, replacement, address, epoch, timestamp, nonce)
    }

    private fun base(
        address: DeviceAddress = phone,
        current: DeviceAuthenticationKeyPair = key1,
        replacement: DeviceAuthenticationKeyPair = key2,
        epoch: Long = 7,
        timestamp: Instant = this.timestamp,
        nonce: RequestNonce = nonce1,
    ) = Case(address, current, replacement, epoch, timestamp, nonce)

    private class Vector(
        val case: Case,
        val authorizationInput: String,
        val proofOfPossessionInput: String,
        val rotationId: String,
        val authorizationSignature: String,
        val proofOfPossession: String,
    )

    private val vectors by lazy {
        mapOf(
            "base" to Vector(
                base(),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "6cd52602d473e98001a88093c6613d8913a54c47d6d924fcf2d9ee1f45152c4b",
                "60d770a03e575a35a357c2a724ed87d01d29bdfd36322f74b41c43d978a868f2a366cf5b39ea47f123ddb3abc9873bce43c1799bab03fd09ced777c222eb5602",
                "9c2832e5f587b53235e162adc74f93bdb43adb8232b8c33bc3e79423b243af4584205b9ff94ccbb2e4da87259e1a5d1f1b5a5cfe6a19f468ddb6b98dd39a1b01",
            ),
            "other device" to Vector(
                base(address = tablet),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000067461" +
                    "626c65742543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2b" +
                    "aa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "00067461626c65742543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe" +
                    "6ab21e2baa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "6104953fb1f0484fba2524d2a66b015e036edc8fedf6a69fafaf6ebb0250604c",
                "d32329ffd59bdb2ce1da2feca17d57bb6078990b442585fff19679e102eb764fc93ed98419dae325381379888a50ad78ecb411a9ff113cc9652c3336342fd405",
                "5eb46be8e7b81f8f0c4986873ca157ac61d701bd63f07c7d126464fd92b6e9b5ed17c5c12388d0fb792dc4ef63e6156062ae9a37d77d11a02f9077ee37835d06",
            ),
            "other current key" to Vector(
                base(current = key4),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e654fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e654fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "35ead98668c5c66f1476559b800674a1f3b08e68288517bdda0285b503880486",
                "22cf2f2ce1f4920909733f843775c25abad92b0316a0295c6989f25aaa9b5361e0ae79fe12c80ce439a316841a68cfc6b8c3fc0a5b1ccb63c688690170470601",
                "0f557c88a10604a73fe3617a3c8c4ea5ad839678b0ae422c2b618b0b94f88694bd5f8c3fb19954378449e89b313135e6cce9fc2ff0d58a5c2a159a228c486108",
            ),
            "other replacement key" to Vector(
                base(replacement = key3),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559dcd14b37f956e953194ff7fb73b3d81dcc561d61a" +
                    "7538094b7c3e1a643ee5f3aa00000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559dcd14b37f956e953194ff7fb73b3d81dc" +
                    "c561d61a7538094b7c3e1a643ee5f3aa00000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "6b6ff29b6a011128ce4d928e966ef9cb47f85b2bcef504e733f403d088f74def",
                "19684a544ed48cc2936320cc57ec14981daee2ed5339552bcf0a0083b9ab35babaf9a4db378a2447ac8ab09ed2993787e9329e65733155b5c5f91fb225290a0f",
                "71c6857168cc2eb9e5a3ac09e2ea6858956abd328d1c24a13f1f133c1adf401cff85010f63ab9b430176d3e19877f6231db157b2a3b7d6aa66f0bfdbc4c8f400",
            ),
            "other epoch" to Vector(
                base(epoch = 8),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd500000000000000080000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd500000000000000080000019b76daa800000102030405060708090a0b0c0d0e0f",
                "9174aacbd0fc4d214d6cef26d2c5a6ab1cb8c5e9da4bc1635983b62383946865",
                "203bcaf89c6cc538bbcfce18353c0308e2eceded46133ccaddd507c553aeb83a630033c24a128781f8d965931148c7223f7b95a12dc0ae9cb27c68349e53500d",
                "93a59d8b498ba734ea5eb4961b5178f32d5ee6bebae81bc8a7ae92d4d22519e3c27356523ea2befd715271522b81f4178b929ec1e2fe41363085192014fe4006",
            ),
            "max epoch" to Vector(
                base(epoch = Long.MAX_VALUE),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd57fffffffffffffff0000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd57fffffffffffffff0000019b76daa800000102030405060708090a0b0c0d0e0f",
                "cf975bbf906bcf449324ca817cf33aad2d528b829518c9067f60f01b67c360fc",
                "32d0316ea883bfb17a68a5911078af94205be192f8ef52fb586434a4c1a4509aff15bf1c8e155accf4dc8dd9fb26e33ffd173733e6040c7a12c009300638ab0e",
                "6e441d954865efcde9441822e331ea8b7e1edd531e478a3755604d08cbd0de61f4de567959b1ff047f9b8f43609c78aec3633b6565d9b8349eeac908c376750c",
            ),
            "other timestamp" to Vector(
                base(timestamp = Instant.fromEpochMilliseconds(0)),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd500000000000000070000000000000000000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd500000000000000070000000000000000000102030405060708090a0b0c0d0e0f",
                "e75346c811703b4ef955e36bd5ee33271a203bc4472a6954b0606fbca59d4612",
                "d5f13788f3d70ae28b94d3fd9a4bc49742b1aad497e9bba480be743c39d7112574e5013a5837df314f6771d119173c50c987dfd6f3747a1d45a469051c70280b",
                "a8763b153067f10dc02d026c49ac5b13f301b0f766a56995686a9fef48f00fb9908c914f44fb86c64ad7f8a07ef57b3623879a85d4413989bb552eaed331420d",
            ),
            "other nonce" to Vector(
                base(nonce = nonce3),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000005616c696365000000057068" +
                    "6f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2baa" +
                    "0617795b7d43a63482993fd500000000000000070000019b76daa800fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000005616c6963650000" +
                    "000570686f6e652543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6a" +
                    "b21e2baa0617795b7d43a63482993fd500000000000000070000019b76daa800fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "b8f902b63121560c8934afce1e501e8c19590dd8e3e198f11b344e9bbca1fbf4",
                "d71084c6b48332d4d47956bde250832c44b1e4202426ee366d22729e1d07016fd492fde0bd96184669b7ba07650667dbafb8356bb3924bf6ba344a4aefa0930b",
                "3940e8c5fc35fde18a4c604b4f09e7be84a7a6739779174a029ea46cdd37de3e47f551fe4a160fcf29c93bb10116c9fa42018c909696c20940227c822dae5f0f",
            ),
            "encoded" to Vector(
                base(address = encoded),
                "000000244b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d763100000006c3a420622f630000000564" +
                    "65767e312543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe6ab21e2b" +
                    "aa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "000000284b5365637572654d6573736167652d44657669636541757468526f746174696f6e2d506f502d763100000006c3a420622f6300" +
                    "0000056465767e312543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d174553b456dddfc6908ecab1c101fe" +
                    "6ab21e2baa0617795b7d43a63482993fd500000000000000070000019b76daa800000102030405060708090a0b0c0d0e0f",
                "809ac784363739884f1c5d228f9e8f2f593b38c2f9ee5b095a2d0d2caa6a0416",
                "8758780a0385097ee6f9f1fb434a1089e80e1597ed15dcc00f9dbaeb8013560abdccd3fb9d523f41cfb4e6141c9b15401836486cc7379bb8ef3ecc0e8aa22b0c",
                "a0bb1ed6ed77ead6bc8526abbfed179679039cccec299483147b71c922078f838a0774b0abc344c6b67f30d2c02704a9aade6045c6865c0b3690ccd8fce95b07",
            ),
        )
    }

    private val baseAuthorization get() = base().authorization()

    @Test
    fun keyPairsMatchTheirSeeds() {
        for (keyPair in listOf(key1, key2, key3, key4)) {
            val data = "check".encodeToByteArray()
            assertTrue(Ed25519.verify(keyPair.publicKey, data, Ed25519.sign(keyPair.privateKey, data)))
        }
    }

    @Test
    fun authorizationInputsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.authorizationInput, DeviceAuthenticationRotation.authorizationInput(vector.case.authorization().statement).toHex(), name)
        }
    }

    @Test
    fun proofOfPossessionInputsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.proofOfPossessionInput, DeviceAuthenticationRotation.proofOfPossessionInput(vector.case.authorization().statement).toHex(), name)
        }
    }

    @Test
    fun rotationIdsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.rotationId, DeviceAuthenticationRotation.rotationId(vector.case.authorization().statement).bytes.toHex(), name)
        }
    }

    @Test
    fun signaturesAreFrozen() {
        // Ed25519 is deterministic, so the signatures are part of the vectors.
        for ((name, vector) in vectors) {
            val authorization = vector.case.authorization()
            assertEquals(vector.authorizationSignature, authorization.authorizationSignature.toHex(), name)
            assertEquals(vector.proofOfPossession, authorization.proofOfPossession.toHex(), name)
        }
    }

    @Test
    fun frozenSignaturesVerify() {
        for ((name, vector) in vectors) {
            val statement = vector.case.authorization().statement
            val authorization = DeviceAuthenticationRotationAuthorization(statement, hex(vector.authorizationSignature), hex(vector.proofOfPossession))
            assertTrue(DeviceAuthenticationRotation.verifyAuthorization(vector.case.current.publicKey, authorization), name)
            assertTrue(DeviceAuthenticationRotation.verifyProofOfPossession(authorization), name)
        }
    }

    @Test
    fun everyFieldChangesTheRotationId() {
        val ids = vectors.values.map { it.rotationId }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun statementCarriesItsFields() {
        val statement = baseAuthorization.statement
        assertEquals(phone, statement.address)
        assertContentEquals(key1.publicKey, statement.currentPublicKey)
        assertContentEquals(key2.publicKey, statement.replacementPublicKey)
        assertEquals(7, statement.expectedAuthEpoch)
        assertEquals(timestamp, statement.timestamp)
        assertEquals(nonce1, statement.nonce)
    }

    @Test
    fun createTruncatesTheTimestampToMilliseconds() {
        val precise = Instant.fromEpochSeconds(1_767_225_600, 123_456_789)
        val authorization = DeviceAuthenticationRotation.create(key1, key2, phone, 7, precise, nonce1)
        assertEquals(Instant.fromEpochMilliseconds(1_767_225_600_123), authorization.statement.timestamp)
        assertTrue(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, authorization))
    }

    private fun tampered(
        address: DeviceAddress = phone,
        current: ByteArray = key1.publicKey,
        replacement: ByteArray = key2.publicKey,
        epoch: Long = 7,
        timestamp: Instant = this.timestamp,
        nonce: RequestNonce = nonce1,
    ): DeviceAuthenticationRotationAuthorization {
        val original = baseAuthorization
        return DeviceAuthenticationRotationAuthorization(
            DeviceAuthenticationRotationStatement(address, current, replacement, epoch, timestamp, nonce),
            original.authorizationSignature,
            original.proofOfPossession,
        )
    }

    @Test
    fun anyTamperedFieldBreaksBothProofs() {
        val cases = mapOf(
            "address" to tampered(address = tablet),
            "current key" to tampered(current = key4.publicKey),
            "replacement key" to tampered(replacement = key3.publicKey),
            "epoch" to tampered(epoch = 8),
            "timestamp" to tampered(timestamp = timestamp + kotlin.time.Duration.parse("1ms")),
            "nonce" to tampered(nonce = nonce3),
        )
        for ((name, authorization) in cases) {
            assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, authorization), name)
            assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key4.publicKey, authorization), name)
            assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(authorization), name)
        }
    }

    @Test
    fun authorizationNeedsTheCurrentKey() {
        // Signed by K4 while naming K1 as current key: the registered key K1 rejects it.
        val statement = baseAuthorization.statement
        val wrongSigner = DeviceAuthenticationRotationAuthorization(
            statement,
            Ed25519.sign(key4.privateKey, DeviceAuthenticationRotation.authorizationInput(statement)),
            baseAuthorization.proofOfPossession,
        )
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, wrongSigner))
        assertTrue(DeviceAuthenticationRotation.verifyProofOfPossession(wrongSigner))
        // The right signature does not verify with another registered key.
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key4.publicKey, baseAuthorization))
    }

    @Test
    fun proofOfPossessionNeedsTheReplacementKey() {
        val statement = baseAuthorization.statement
        val wrongSigner = DeviceAuthenticationRotationAuthorization(
            statement,
            baseAuthorization.authorizationSignature,
            Ed25519.sign(key3.privateKey, DeviceAuthenticationRotation.proofOfPossessionInput(statement)),
        )
        assertTrue(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, wrongSigner))
        assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(wrongSigner))
    }

    @Test
    fun swappedSignaturesDoNotVerify() {
        // The authorization and the proof of possession cover different domains.
        val swapped = DeviceAuthenticationRotationAuthorization(
            baseAuthorization.statement,
            Ed25519.sign(key1.privateKey, DeviceAuthenticationRotation.proofOfPossessionInput(baseAuthorization.statement)),
            Ed25519.sign(key2.privateKey, DeviceAuthenticationRotation.authorizationInput(baseAuthorization.statement)),
        )
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, swapped))
        assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(swapped))
    }

    @Test
    fun malformedSignaturesAreRejected() {
        val zero = DeviceAuthenticationRotationAuthorization(baseAuthorization.statement, ByteArray(64), ByteArray(64))
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, zero))
        assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(zero))
        val flipped = baseAuthorization.authorizationSignature.also { it[10] = (it[10].toInt() xor 1).toByte() }
        assertFalse(
            DeviceAuthenticationRotation.verifyAuthorization(
                key1.publicKey,
                DeviceAuthenticationRotationAuthorization(baseAuthorization.statement, flipped, baseAuthorization.proofOfPossession),
            ),
        )
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(ByteArray(31), baseAuthorization))
        assertFailsWith<IllegalArgumentException> {
            DeviceAuthenticationRotationAuthorization(baseAuthorization.statement, ByteArray(63), ByteArray(64))
        }
        assertFailsWith<IllegalArgumentException> {
            DeviceAuthenticationRotationAuthorization(baseAuthorization.statement, ByteArray(64), ByteArray(65))
        }
    }

    @Test
    fun sameKeyRotationIsRejected() {
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotation.create(key1, key1, phone, 7, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> {
            DeviceAuthenticationRotationStatement(phone, key1.publicKey, key1.publicKey, 7, timestamp, nonce1)
        }
    }

    @Test
    fun statementRejectsInvalidFields() {
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationStatement(phone, ByteArray(31), key2.publicKey, 7, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationStatement(phone, key1.publicKey, ByteArray(33), 7, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationStatement(phone, key1.publicKey, key2.publicKey, 0, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationStatement(phone, key1.publicKey, key2.publicKey, -1, timestamp, nonce1) }
        assertFailsWith<IllegalArgumentException> {
            DeviceAuthenticationRotationStatement(phone, key1.publicKey, key2.publicKey, 7, Instant.fromEpochMilliseconds(-1), nonce1)
        }
        assertFailsWith<IllegalArgumentException> {
            DeviceAuthenticationRotationStatement(phone, key1.publicKey, key2.publicKey, 7, Instant.fromEpochSeconds(1, 1), nonce1)
        }
    }

    @Test
    fun statementCopiesKeys() {
        val current = key1.publicKey.copyOf()
        val statement = DeviceAuthenticationRotationStatement(phone, current, key2.publicKey, 7, timestamp, nonce1)
        current.fill(0)
        statement.currentPublicKey.fill(0)
        assertContentEquals(key1.publicKey, statement.currentPublicKey)
    }

    @Test
    fun rotationIdIsAValue() {
        val id = DeviceAuthenticationRotation.rotationId(baseAuthorization.statement)
        assertEquals(id, DeviceAuthenticationRotationId(id.bytes))
        assertNotEquals(id, DeviceAuthenticationRotation.rotationId(base(nonce = nonce3).authorization().statement))
        assertEquals("DeviceAuthenticationRotationId(<redacted>)", id.toString())
        assertFailsWith<IllegalArgumentException> { DeviceAuthenticationRotationId(ByteArray(31)) }
    }

    @Test
    fun toStringNeverShowsKeysOrSignatures() {
        val text = baseAuthorization.toString()
        for (secret in listOf(key1.publicKey, key2.publicKey, baseAuthorization.authorizationSignature, baseAuthorization.proofOfPossession)) {
            assertFalse(text.contains(secret.toHex()))
        }
    }

    // Domain separation: none of the other signed constructions verifies as a rotation proof and vice versa.

    @Test
    fun recoverySignaturesAreNotRotationSignatures() {
        // Same keys, same device pair, same timestamp and nonce.
        val request = DeviceRecovery.prepare(key2, phone, tablet, timestamp, nonce1)
        val recovery = DeviceRecovery.authorize(key1, request)
        val asRotation = DeviceAuthenticationRotationAuthorization(
            baseAuthorization.statement,
            recovery.authorizerSignature,
            request.proofOfPossession,
        )
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, asRotation))
        assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(asRotation))
        // The rotation input under the recovery domains, signed by the same keys, does not verify either.
        val rotationStatement = DeviceAuthenticationRotation.statement(baseAuthorization.statement)
        val underRecoveryDomain = BinaryWriter().apply {
            bytes(ProtocolConstants.DEVICE_RECOVERY_DOMAIN.encodeToByteArray())
            fixed(rotationStatement)
        }.toByteArray()
        val forged = DeviceAuthenticationRotationAuthorization(
            baseAuthorization.statement,
            Ed25519.sign(key1.privateKey, underRecoveryDomain),
            baseAuthorization.proofOfPossession,
        )
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(key1.publicKey, forged))
    }

    @Test
    fun rotationSignaturesAreNotRecoverySignatures() {
        val request = DeviceRecovery.prepare(key2, phone, tablet, timestamp, nonce1)
        val asRecovery = DeviceRecoveryAuthorization(
            DeviceRecoveryRequest(phone, tablet, key2.publicKey, timestamp, nonce1, baseAuthorization.proofOfPossession),
            baseAuthorization.authorizationSignature,
        )
        assertFalse(DeviceRecovery.verifyAuthorization(key1.publicKey, asRecovery))
        assertFalse(DeviceRecovery.verifyProofOfPossession(asRecovery.request))
        assertTrue(DeviceRecovery.verifyProofOfPossession(request))
    }

    @Test
    fun rotationAndServerAuthSignaturesAreSeparate() {
        val request = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.REGISTRATION_ROTATION), ByteArray(0))
        val serverAuth = ServerRequestAuthentication.sign(key1, request, timestamp, nonce1)
        assertFalse(
            DeviceAuthenticationRotation.verifyAuthorization(
                key1.publicKey,
                DeviceAuthenticationRotationAuthorization(baseAuthorization.statement, serverAuth.signature, baseAuthorization.proofOfPossession),
            ),
        )
        assertFalse(
            ServerRequestAuthentication.verify(
                key1.publicKey,
                request,
                RequestAuthentication(timestamp, nonce1, baseAuthorization.authorizationSignature),
            ),
        )
    }

    @Test
    fun domainsAreDistinct() {
        val domains = listOf(
            ProtocolConstants.DEVICE_AUTH_ROTATION_DOMAIN,
            ProtocolConstants.DEVICE_AUTH_ROTATION_POP_DOMAIN,
            ProtocolConstants.DEVICE_AUTH_ROTATION_ID_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_POP_DOMAIN,
            ProtocolConstants.DEVICE_RECOVERY_ID_DOMAIN,
            ProtocolConstants.SERVER_AUTH_DOMAIN,
            ProtocolConstants.SAFETY_NUMBER_DOMAIN,
        )
        assertEquals(domains.size, domains.toSet().size)
        assertEquals("KSecureMessage-DeviceAuthRotation-v1", ProtocolConstants.DEVICE_AUTH_ROTATION_DOMAIN)
        assertEquals("KSecureMessage-DeviceAuthRotation-PoP-v1", ProtocolConstants.DEVICE_AUTH_ROTATION_POP_DOMAIN)
        assertEquals("KSecureMessage-DeviceAuthRotationId-v1", ProtocolConstants.DEVICE_AUTH_ROTATION_ID_DOMAIN)
    }
}
