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
 * Frozen vectors of device recovery format version 1
 * (docs/device-recovery.md). Every recovery a server accepted and every
 * transferred recovery blob depends on them. Computed independently (Python
 * struct, hashlib and the `cryptography` package's Ed25519) from the
 * documented layout.
 */
class DeviceRecoveryTest {
    private fun keyPair(first: Int, publicKey: String) =
        DeviceAuthenticationKeyPair(hex(publicKey), ByteArray(32) { (first + it).toByte() })

    private val authorizer1 = keyPair(0x40, "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")
    private val authorizer2 = keyPair(0xA0, "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4")
    private val replacement1 = keyPair(0x60, "174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5")
    private val replacement2 = keyPair(0x80, "cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa")

    private val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val desktop = DeviceAddress(UserId("alice"), DeviceId("desktop"))
    private val encodedTarget = DeviceAddress(UserId("ä b/c"), DeviceId("dev~1"))
    private val encodedAuthorizer = DeviceAddress(UserId("ä b/c"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
    private val timestamp = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val nonce1 = RequestNonce(ByteArray(16) { it.toByte() })
    private val nonce3 = RequestNonce(ByteArray(16) { (0xFF - it).toByte() })

    private class Case(
        val target: DeviceAddress,
        val authorizer: DeviceAddress,
        val replacement: DeviceAuthenticationKeyPair,
        val timestamp: Instant,
        val nonce: RequestNonce,
        val authorizerKeyPair: DeviceAuthenticationKeyPair,
    ) {
        fun request() = DeviceRecovery.prepare(replacement, target, authorizer, timestamp, nonce)
        fun authorization() = DeviceRecovery.authorize(authorizerKeyPair, request())
    }

    private fun base(
        target: DeviceAddress = laptop,
        authorizer: DeviceAddress = phone,
        replacement: DeviceAuthenticationKeyPair = replacement1,
        timestamp: Instant = this.timestamp,
        nonce: RequestNonce = nonce1,
        authorizerKeyPair: DeviceAuthenticationKeyPair = authorizer1,
    ) = Case(target, authorizer, replacement, timestamp, nonce, authorizerKeyPair)

    private class Vector(
        val case: Case,
        val authorizationInput: String,
        val proofOfPossessionInput: String,
        val recoveryId: String,
        val proofOfPossession: String,
        val authorizerSignature: String,
    )

    private val vectors by lazy {
        mapOf(
            "base" to Vector(
                base(),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000066c6170746f7000" +
                    "000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000019b76daa8" +
                    "00000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c696365000000066c6170" +
                    "746f7000000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5000001" +
                    "9b76daa800000102030405060708090a0b0c0d0e0f",
                "ce3851becb129f738b06a0edc5efca015941d585f6df48c7adca235a93402744",
                "f62c69526c59c650d3f7a5b634a535f3a50661ed06b767a4354b3e1f303909d2844f474e10087d5a9eb9e0e3c831b6e050a3eb852e36fd92ec24143ed94fe309",
                "0edf482a4533124417de54d2d24df44c540851e8f6ff2dac5001767667ec4af7f3579f58c4c48137eaf036b1781bd6be35c2b3c1002b2a85848692034e469c01",
            ),
            "other target" to Vector(
                base(target = tablet),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000067461626c657400" +
                    "000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000019b76daa8" +
                    "00000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c69636500000006746162" +
                    "6c657400000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5000001" +
                    "9b76daa800000102030405060708090a0b0c0d0e0f",
                "5e4b0e0647b6ac465041d6907c9e9329da74ef58fa1c5fa03bb3476761311ef3",
                "2cc020a5517151a0cc2e6d9b0a147f8231596ef4ae328004d2ecfddfba132527cf04a8f894cd98822e85b93f048025d313a529f87e0d316834e7b93b34b7220c",
                "8079584ad3fdac800606e2f0e4e9bdd24d9aab1d0e8d4cf1ae93e3bfd1138253012aa4fbdf39da6430dafb5e506e3f39f04db29aaf4a00ce46da6b8f796ba102",
            ),
            "other key" to Vector(
                base(replacement = replacement2),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000066c6170746f7000" +
                    "000005616c6963650000000570686f6e65cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa0000019b76daa8" +
                    "00000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c696365000000066c6170" +
                    "746f7000000005616c6963650000000570686f6e65cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa000001" +
                    "9b76daa800000102030405060708090a0b0c0d0e0f",
                "6b5bf0581029991f4301cc15f9e2ded235643ff61e97b2fc15c0a6210dcb2632",
                "0dcf281ec491d528962b5e835514deb64779bc12ed85b8401f3bc156bbae0d77c5ec50ed54c52f53e585a08dd7a6f8d798da4d3d01a7e8a41bc053ca4b9f6909",
                "86b9de957d26e3b198c11f1d1321e56b37eb99510e0b6c5f60f9bf5fbe8f2f926eabbe9d0ca9061e81d9ffc84e99605a3fa4259049a608d7c6b10ebcdcb23d06",
            ),
            "other authorizer" to Vector(
                base(authorizer = desktop, authorizerKeyPair = authorizer2),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000066c6170746f7000" +
                    "000005616c696365000000076465736b746f70174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000019b76" +
                    "daa800000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c696365000000066c6170" +
                    "746f7000000005616c696365000000076465736b746f70174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd500" +
                    "00019b76daa800000102030405060708090a0b0c0d0e0f",
                "99b5bafcdd76437bd5e0419ef90c633346e1e0352ac85822f90a88aafb6db14b",
                "039e04c357149a39619b9f25d077a93f9e0cbef858d818eb8637ef3c06a628e4192b9c06c5596a81d0c6a8ebf53f3c2cd4748eaad0da34919e3eb95559c48d01",
                "d7504cef22810e9bc9434e96a1097ed347235219bc9eb02596c76ae6e80651637ad2a360538130ec35ffe0c5380c84f2e96b5633760a22fe8125a480d53fad0e",
            ),
            "other timestamp" to Vector(
                base(timestamp = Instant.fromEpochMilliseconds(0)),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000066c6170746f7000" +
                    "000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd500000000000000" +
                    "00000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c696365000000066c6170" +
                    "746f7000000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5000000" +
                    "0000000000000102030405060708090a0b0c0d0e0f",
                "26aeae5637ca097e4d274d492c9f5e8798d8bb07a305151a04b5d77ce35bf08e",
                "1f4682be7de0bbb4a95eb7f5e8f0f1782fa026c5b21181ae87011ee676be1c1b2c3b7f3f5fbd6d0852eb1dce3e5f99a8efc3cfd41a9025c56d556228e3fd6b07",
                "48187eecec342ed3519bbda09a5a24b16861d93800ba8e516ce2361f3cdb2d551cd5ffac8fc5520669c0a969bbf04baf041e384b7d36f203dcd03236b9e3330b",
            ),
            "other nonce" to Vector(
                base(nonce = nonce3),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000005616c696365000000066c6170746f7000" +
                    "000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000019b76daa8" +
                    "00fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000005616c696365000000066c6170" +
                    "746f7000000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5000001" +
                    "9b76daa800fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "d3399fe70025b3595295569affde4071bc7d297d830b7e9323074a9fbc3fa00f",
                "c7daedffe4d28b67c293f72814bee109a20fa739bc0bbcd5d5be4b72e4bf747d633360a3857e59f411261ac89032435e1a51296021b86dab6d5731661f5c510b",
                "745f1d19e49912eb49839798f8cbd312c28229b4ad33a0a7f288356e13ff8a6c61e8b404a60a8187e23bc9a74021ec997811d683c7fcc329712c144c1dcca704",
            ),
            "encoded" to Vector(
                base(target = encodedTarget, authorizer = encodedAuthorizer),
                "000000204b5365637572654d6573736167652d4465766963655265636f766572792d763100000006c3a420622f63000000056465767e3100" +
                    "000006c3a420622f630000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000019b76da" +
                    "a800000102030405060708090a0b0c0d0e0f",
                "000000244b5365637572654d6573736167652d4465766963655265636f766572792d506f502d763100000006c3a420622f63000000056465" +
                    "767e3100000006c3a420622f630000000570686f6e65174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000" +
                    "019b76daa800000102030405060708090a0b0c0d0e0f",
                "7207532dc5ae6b879ba51efd3686283fd7555b48b7d8c8257da6c7db58130c6e",
                "82aea52362ffe78de36a1686a0c26ad72ae273ea909a56f208b66157b2d1092506c0e0c070e7d0f0980104da84b5ac51758e6dc20dd791e0462638d67a8e0e08",
                "c72e43b021a0310b1ea7e7c59f38f042bb2183da3f1e586630a4a28d4893ca26f247f07a372166e52922f94356638ee56f63e7cae663619bbe817da9ed8a490f",
            ),
        )
    }

    private val requestBlob =
        "010100000005616c696365000000066c6170746f7000000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab2" +
            "1e2baa0617795b7d43a63482993fd50000019b76daa800000102030405060708090a0b0c0d0e0ff62c69526c59c650d3f7a5b634a535f3a5" +
            "0661ed06b767a4354b3e1f303909d2844f474e10087d5a9eb9e0e3c831b6e050a3eb852e36fd92ec24143ed94fe309"

    private val authorizationBlob =
        "010200000005616c696365000000066c6170746f7000000005616c6963650000000570686f6e65174553b456dddfc6908ecab1c101fe6ab2" +
            "1e2baa0617795b7d43a63482993fd50000019b76daa800000102030405060708090a0b0c0d0e0ff62c69526c59c650d3f7a5b634a535f3a5" +
            "0661ed06b767a4354b3e1f303909d2844f474e10087d5a9eb9e0e3c831b6e050a3eb852e36fd92ec24143ed94fe3090edf482a4533124417" +
            "de54d2d24df44c540851e8f6ff2dac5001767667ec4af7f3579f58c4c48137eaf036b1781bd6be35c2b3c1002b2a85848692034e469c01"

    @Test
    fun keyPairsMatchTheirSeeds() {
        // The public keys above come from the reference implementation; the
        // library's signatures must verify with them.
        for (keyPair in listOf(authorizer1, authorizer2, replacement1, replacement2)) {
            val data = "check".encodeToByteArray()
            assertTrue(Ed25519.verify(keyPair.publicKey, data, Ed25519.sign(keyPair.privateKey, data)))
        }
    }

    @Test
    fun authorizationInputsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.authorizationInput, DeviceRecovery.authorizationInput(vector.case.request()).toHex(), name)
        }
    }

    @Test
    fun proofOfPossessionInputsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.proofOfPossessionInput, DeviceRecovery.proofOfPossessionInput(vector.case.request()).toHex(), name)
        }
    }

    @Test
    fun recoveryIdsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.recoveryId, DeviceRecovery.recoveryId(vector.case.request()).bytes.toHex(), name)
        }
    }

    @Test
    fun signaturesAreFrozen() {
        for ((name, vector) in vectors) {
            val authorization = vector.case.authorization()
            assertEquals(vector.proofOfPossession, authorization.request.proofOfPossession.toHex(), name)
            assertEquals(vector.authorizerSignature, authorization.authorizerSignature.toHex(), name)
        }
    }

    @Test
    fun frozenSignaturesVerify() {
        for ((name, vector) in vectors) {
            val case = vector.case
            val request = DeviceRecoveryRequest(
                case.target, case.authorizer, case.replacement.publicKey, case.timestamp, case.nonce, hex(vector.proofOfPossession),
            )
            val authorization = DeviceRecoveryAuthorization(request, hex(vector.authorizerSignature))
            assertTrue(DeviceRecovery.verifyProofOfPossession(request), name)
            assertTrue(DeviceRecovery.verifyAuthorization(case.authorizerKeyPair.publicKey, authorization), name)
        }
    }

    @Test
    fun everyFieldChangesTheStatement() {
        val inputs = vectors.values.map { it.authorizationInput }
        assertEquals(inputs.size, inputs.toSet().size)
        val ids = vectors.values.map { it.recoveryId }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun transferEncodingIsFrozen() {
        val authorization = base().authorization()
        assertEquals(requestBlob, DeviceRecoveryCodec.encodeRequest(authorization.request).toHex())
        assertEquals(authorizationBlob, DeviceRecoveryCodec.encodeAuthorization(authorization).toHex())
    }

    @Test
    fun transferEncodingRoundTrips() {
        val decoded = DeviceRecoveryCodec.decodeAuthorization(hex(authorizationBlob))
        assertEquals(laptop, decoded.request.target)
        assertEquals(phone, decoded.request.authorizer)
        assertContentEquals(replacement1.publicKey, decoded.request.replacementPublicKey)
        assertEquals(timestamp, decoded.request.timestamp)
        assertEquals(nonce1, decoded.request.nonce)
        assertTrue(DeviceRecovery.verifyProofOfPossession(decoded.request))
        assertTrue(DeviceRecovery.verifyAuthorization(authorizer1.publicKey, decoded))
        val request = DeviceRecoveryCodec.decodeRequest(hex(requestBlob))
        assertContentEquals(hex(requestBlob), DeviceRecoveryCodec.encodeRequest(request))
        val encoded = base(target = encodedTarget, authorizer = encodedAuthorizer).authorization()
        val roundTrip = DeviceRecoveryCodec.decodeAuthorization(DeviceRecoveryCodec.encodeAuthorization(encoded))
        assertEquals(encodedTarget, roundTrip.request.target)
        assertEquals(encodedAuthorizer, roundTrip.request.authorizer)
    }

    @Test
    fun malformedTransferEncodingIsRejected() {
        val request = hex(requestBlob)
        val authorization = hex(authorizationBlob)
        val cases = listOf(
            byteArrayOf(),
            request.copyOf(request.size - 1),
            request + 0,
            authorization,                                       // other kind
            request.copyOf().also { it[0] = 2 },                 // version
            request.copyOf().also { it[5] = 0x7F },              // length beyond the input
            // target user "alice" with an invalid UTF-8 byte
            request.copyOf().also { it[6] = 0xC3.toByte() },
            // negative timestamp
            request.copyOf().also { it[2 + 9 + 10 + 9 + 9 + 32] = 0x80.toByte() },
        )
        for ((index, bytes) in cases.withIndex()) {
            assertFailsWith<IllegalArgumentException>("case $index") { DeviceRecoveryCodec.decodeRequest(bytes) }
        }
        assertFailsWith<IllegalArgumentException> { DeviceRecoveryCodec.decodeAuthorization(request) }
        assertFailsWith<IllegalArgumentException> { DeviceRecoveryCodec.decodeAuthorization(authorization + 0) }
        assertFailsWith<IllegalArgumentException> { DeviceRecoveryCodec.decodeAuthorization(authorization.copyOf(authorization.size - 1)) }
    }

    private fun DeviceRecoveryRequest.copy(
        target: DeviceAddress = this.target,
        authorizer: DeviceAddress = this.authorizer,
        replacementPublicKey: ByteArray = this.replacementPublicKey,
        timestamp: Instant = this.timestamp,
        nonce: RequestNonce = this.nonce,
        proofOfPossession: ByteArray = this.proofOfPossession,
    ) = DeviceRecoveryRequest(target, authorizer, replacementPublicKey, timestamp, nonce, proofOfPossession)

    private fun tampered(authorization: DeviceRecoveryAuthorization): List<Pair<String, DeviceRecoveryRequest>> {
        val request = authorization.request
        return listOf(
            "target" to request.copy(target = tablet),
            "target user" to request.copy(target = DeviceAddress(UserId("bob"), DeviceId("laptop"))),
            "replacement key" to request.copy(replacementPublicKey = replacement2.publicKey),
            "authorizer" to request.copy(authorizer = desktop),
            "timestamp" to request.copy(timestamp = timestamp + kotlin.time.Duration.parse("1ms")),
            "nonce" to request.copy(nonce = nonce3),
        )
    }

    @Test
    fun validAuthorizationAndProofVerify() {
        val authorization = base().authorization()
        assertTrue(DeviceRecovery.verifyProofOfPossession(authorization.request))
        assertTrue(DeviceRecovery.verifyAuthorization(authorizer1.publicKey, authorization))
    }

    @Test
    fun everyTamperedFieldBreaksBothSignatures() {
        val authorization = base().authorization()
        for ((field, request) in tampered(authorization)) {
            assertFalse(DeviceRecovery.verifyProofOfPossession(request), field)
            assertFalse(
                DeviceRecovery.verifyAuthorization(authorizer1.publicKey, DeviceRecoveryAuthorization(request, authorization.authorizerSignature)),
                field,
            )
        }
    }

    @Test
    fun wrongKeysDoNotVerify() {
        val authorization = base().authorization()
        assertFalse(DeviceRecovery.verifyAuthorization(authorizer2.publicKey, authorization))
        assertFalse(DeviceRecovery.verifyAuthorization(replacement1.publicKey, authorization))
        // A proof signed by another key than the named replacement key.
        val forged = DeviceRecovery.prepare(replacement2, laptop, phone, timestamp, nonce1)
            .copy(replacementPublicKey = replacement1.publicKey)
        assertFalse(DeviceRecovery.verifyProofOfPossession(forged))
        assertFalse(DeviceRecovery.verifyAuthorization(ByteArray(31), authorization))
    }

    @Test
    fun malformedSignaturesDoNotVerify() {
        val authorization = base().authorization()
        val flipped = authorization.authorizerSignature.also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(DeviceRecovery.verifyAuthorization(authorizer1.publicKey, DeviceRecoveryAuthorization(authorization.request, flipped)))
        val badPop = authorization.request.proofOfPossession.also { it[63] = (it[63].toInt() xor 0x80).toByte() }
        assertFalse(DeviceRecovery.verifyProofOfPossession(authorization.request.copy(proofOfPossession = badPop)))
        assertFailsWith<IllegalArgumentException> { DeviceRecoveryAuthorization(authorization.request, ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { authorization.request.copy(proofOfPossession = ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { authorization.request.copy(replacementPublicKey = ByteArray(33)) }
    }

    @Test
    fun signaturesDoNotCrossDomains() {
        val authorization = base().authorization()
        val request = authorization.request
        // The authorizer's signature is no proof of possession and vice versa,
        // even when the authorizer's key is named as replacement key.
        val selfNamed = DeviceRecovery.prepare(authorizer1, laptop, phone, timestamp, nonce1)
        val authorizedSelfNamed = DeviceRecovery.authorize(authorizer1, selfNamed)
        assertFalse(DeviceRecovery.verifyProofOfPossession(selfNamed.copy(proofOfPossession = authorizedSelfNamed.authorizerSignature)))
        assertFalse(
            DeviceRecovery.verifyAuthorization(authorizer1.publicKey, DeviceRecoveryAuthorization(selfNamed, selfNamed.proofOfPossession)),
        )
        assertFalse(
            DeviceRecovery.verifyAuthorization(replacement1.publicKey, DeviceRecoveryAuthorization(request, request.proofOfPossession)),
        )

        // A ServerAuth-v1 request signature never verifies as recovery signature and vice versa.
        val serverRequest = ServerRequest(laptop, "PUT", ServerApiPaths.device(laptop, ServerApiPaths.REGISTRATION_RECOVERY), DeviceRecovery.statement(request))
        val serverAuth = ServerRequestAuthentication.sign(authorizer1, serverRequest, timestamp, nonce1)
        assertFalse(DeviceRecovery.verifyAuthorization(authorizer1.publicKey, DeviceRecoveryAuthorization(request, serverAuth.signature)))
        val recoveryAsServerAuth = RequestAuthentication(timestamp, nonce1, authorization.authorizerSignature)
        assertFalse(ServerRequestAuthentication.verify(authorizer1.publicKey, serverRequest, recoveryAsServerAuth))
        val popAsServerAuth = RequestAuthentication(timestamp, nonce1, request.proofOfPossession)
        assertFalse(ServerRequestAuthentication.verify(replacement1.publicKey, serverRequest, popAsServerAuth))
    }

    @Test
    fun domainsAreDistinctAndServerAuthIsUnchanged() {
        assertEquals("KSecureMessage-ServerAuth-v1", ProtocolConstants.SERVER_AUTH_DOMAIN)
        assertEquals("KSecureMessage-DeviceRecovery-v1", ProtocolConstants.DEVICE_RECOVERY_DOMAIN)
        assertEquals("KSecureMessage-DeviceRecovery-PoP-v1", ProtocolConstants.DEVICE_RECOVERY_POP_DOMAIN)
        assertEquals("KSecureMessage-DeviceRecoveryId-v1", ProtocolConstants.DEVICE_RECOVERY_ID_DOMAIN)
    }

    @Test
    fun timestampsAreWholeMilliseconds() {
        val request = DeviceRecovery.prepare(replacement1, laptop, phone, Instant.fromEpochSeconds(1_767_225_600, 123_456_789), nonce1)
        assertEquals(Instant.fromEpochMilliseconds(1_767_225_600_123), request.timestamp)
        assertTrue(DeviceRecovery.verifyProofOfPossession(request))
        assertFailsWith<IllegalArgumentException> {
            request.copy(timestamp = Instant.fromEpochSeconds(1_767_225_600, 1))
        }
        assertFailsWith<IllegalArgumentException> { request.copy(timestamp = Instant.fromEpochMilliseconds(-1)) }
    }

    @Test
    fun recoveryIdIgnoresSignaturesButNotFields() {
        val request = base().request()
        assertEquals(DeviceRecovery.recoveryId(request), DeviceRecovery.recoveryId(request.copy(proofOfPossession = ByteArray(64))))
        assertNotEquals(DeviceRecovery.recoveryId(request), DeviceRecovery.recoveryId(request.copy(authorizer = bob)))
        assertEquals("DeviceRecoveryId(<redacted>)", DeviceRecovery.recoveryId(request).toString())
    }
}
