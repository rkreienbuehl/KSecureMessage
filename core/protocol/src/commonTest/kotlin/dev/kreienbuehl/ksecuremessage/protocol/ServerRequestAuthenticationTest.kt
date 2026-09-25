package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlinx.coroutines.test.runTest
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
 * Frozen vectors of the server request authentication format v1
 * (docs/server-authentication.md). Every registered device and signed request
 * depends on them. Computed independently (Python hashlib, urllib.parse.quote
 * and the `cryptography` package's Ed25519) from the documented layout.
 */
class ServerRequestAuthenticationTest {
    private val seed = ByteArray(32) { (0x40 + it).toByte() }
    private val publicKey = hex("2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")
    private val keyPair = DeviceAuthenticationKeyPair(publicKey, seed)

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val timestamp = Instant.fromEpochMilliseconds(1_767_225_600_000)
    private val nonce1 = RequestNonce(ByteArray(16) { it.toByte() })
    private val nonce2 = RequestNonce(ByteArray(16) { (0x10 + it).toByte() })
    private val nonce3 = RequestNonce(ByteArray(16) { (0xFF - it).toByte() })
    private val preKeyBody =
        """{"identityKey":"AAAA","signedPreKey":{"id":1,"publicKey":"BBBB","signature":"CCCC"},"oneTimePreKeys":[]}""".encodeToByteArray()

    private fun get(address: DeviceAddress = alice, body: ByteArray = ByteArray(0)) =
        ServerRequest(address, "GET", ServerApiPaths.device(address, ServerApiPaths.MESSAGES), body)

    private fun putPreKeys(address: DeviceAddress = alice, body: ByteArray = preKeyBody) =
        ServerRequest(address, "PUT", ServerApiPaths.device(address, ServerApiPaths.PRE_KEYS), body)

    private class Vector(val request: ServerRequest, val timestamp: Instant, val nonce: RequestNonce, val input: String, val signature: String)

    private val vectors by lazy {
        mapOf(
            "empty-body GET" to Vector(
                get(), timestamp, nonce1,
                "0000001c4b5365637572654d6573736167652d536572766572417574682d763100000005616c6963650000000570686f6e650000000347455400" +
                    "0000202f76312f646576696365732f616c6963652f70686f6e652f6d65737361676573e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b" +
                    "934ca495991b7852b8550000019b76daa800000102030405060708090a0b0c0d0e0f",
                "e6f7ac86ff38480446b1689fe29a9bd27d9473fbe9ce71134f9b340b6e5ccbe5cdae08a44bed1c538e7e0eac21a9bfce0a2ec66e2fa260e18ac9d9e5f3eeb10c",
            ),
            "prekey PUT" to Vector(
                putPreKeys(), timestamp, nonce2,
                "0000001c4b5365637572654d6573736167652d536572766572417574682d763100000005616c6963650000000570686f6e650000000350555400" +
                    "00001f2f76312f646576696365732f616c6963652f70686f6e652f7072656b657973bd6dba2459bb2d0fec29262c5886230a9172ce66d521be" +
                    "bc850de58f13effaab0000019b76daa800101112131415161718191a1b1c1d1e1f",
                "dde273f8c48b835fed94fa5354be9cdc9fb3a35b673b5d24e9b83ad6b4de82f9974b3b8e50253af1b7679029350cec83d2fa737076e19bed6120120f9403ee01",
            ),
            "other nonce" to Vector(
                get(), timestamp, nonce3,
                "0000001c4b5365637572654d6573736167652d536572766572417574682d763100000005616c6963650000000570686f6e650000000347455400" +
                    "0000202f76312f646576696365732f616c6963652f70686f6e652f6d65737361676573e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b" +
                    "934ca495991b7852b8550000019b76daa800fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                "80f9fbd83940825cf46a1a6728a2e70e34d027c9a82cae26077a9c8b1b2156b664412757e191a01141f8b73c4f329c1264435380d0ef130c5df9d5d3ef5dc509",
            ),
            "epoch timestamp" to Vector(
                get(), Instant.fromEpochMilliseconds(0), nonce1,
                "0000001c4b5365637572654d6573736167652d536572766572417574682d763100000005616c6963650000000570686f6e650000000347455400" +
                    "0000202f76312f646576696365732f616c6963652f70686f6e652f6d65737361676573e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b" +
                    "934ca495991b7852b8550000000000000000000102030405060708090a0b0c0d0e0f",
                "0a5de607783250e99efdd152ab9448151317ab801ffb73fcf5d40f2b7617033cdc5f5f259d6f2c6d13d7d7e001ada8e8a6248b32986aa5a41ad57e9555e4de0b",
            ),
            "encoded path" to Vector(
                putPreKeys(DeviceAddress(UserId("ä b/c"), DeviceId("dev~1.x_y-z")), ByteArray(0)), timestamp, nonce1,
                "0000001c4b5365637572654d6573736167652d536572766572417574682d763100000006c3a420622f630000000b6465767e312e785f792d7a00" +
                    "0000035055540000002e2f76312f646576696365732f25433325413425323062253246632f6465767e312e785f792d7a2f7072656b657973e3" +
                    "b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000019b76daa800000102030405060708090a0b0c0d0e0f",
                "8c3c408ed72e062ba3df3f63e0642a09e04d1985d971702eb81fe36594fda446e57c17763684d72077f0ca63d2c60b961821b2a2816ba2a99b0be624f3c45d07",
            ),
        )
    }

    @Test
    fun canonicalInputsAndSignaturesMatchVectors() {
        for ((name, vector) in vectors) {
            assertEquals(vector.input, ServerRequestAuthentication.canonicalInput(vector.request, vector.timestamp, vector.nonce).toHex(), name)
            val signed = ServerRequestAuthentication.sign(keyPair, vector.request, vector.timestamp, vector.nonce)
            assertEquals(vector.signature, signed.signature.toHex(), name)
            assertEquals(vector.timestamp, signed.timestamp, name)
            assertEquals(vector.nonce, signed.nonce, name)
            assertTrue(ServerRequestAuthentication.verify(publicKey, vector.request, RequestAuthentication(vector.timestamp, vector.nonce, hex(vector.signature))), name)
        }
    }

    @Test
    fun canonicalPathsAreFrozen() {
        assertEquals("/v1/devices/alice/phone/messages", ServerApiPaths.device(alice, ServerApiPaths.MESSAGES))
        assertEquals("/v1/devices/alice/phone/registration", ServerApiPaths.device(alice, ServerApiPaths.REGISTRATION))
        assertEquals("/v1/devices/alice/phone/prekey-bundle", ServerApiPaths.device(alice, ServerApiPaths.PRE_KEY_BUNDLE))
        assertEquals(
            "/v1/devices/%C3%A4%20b%2Fc/dev~1.x_y-z/prekeys",
            ServerApiPaths.device(DeviceAddress(UserId("ä b/c"), DeviceId("dev~1.x_y-z")), ServerApiPaths.PRE_KEYS),
        )
        assertEquals("%3F%23%25%2B", ServerApiPaths.encodeSegment("?#%+"))
    }

    @Test
    fun emptyBodyHashIsSha256OfNothing() {
        val input = ServerRequestAuthentication.canonicalInput(get(), timestamp, nonce1)
        val hash = input.copyOfRange(input.size - 16 - 8 - 32, input.size - 16 - 8)
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash.toHex())
    }

    private fun signed(request: ServerRequest = putPreKeys()) = ServerRequestAuthentication.sign(keyPair, request, timestamp, nonce1)

    private fun verifies(request: ServerRequest, authentication: RequestAuthentication, key: ByteArray = publicKey) =
        ServerRequestAuthentication.verify(key, request, authentication)

    @Test
    fun freshKeysSignAndVerify() = runTest {
        val key = KodiumProtocolEngine().createDeviceAuthenticationKey()
        assertEquals(ServerRequestAuthentication.PUBLIC_KEY_SIZE, key.publicKey.size)
        assertEquals(32, key.privateKey.size)
        val authentication = ServerRequestAuthentication.sign(key, putPreKeys(), timestamp)
        assertEquals(ServerRequestAuthentication.SIGNATURE_SIZE, authentication.signature.size)
        assertTrue(verifies(putPreKeys(), authentication, key.publicKey))
        assertFalse(verifies(putPreKeys(), authentication), "another device's key")
        assertNotEquals(key.publicKey.toHex(), KodiumProtocolEngine().createDeviceAuthenticationKey().publicKey.toHex())
    }

    @Test
    fun everyBodyByteIsBound() {
        val authentication = signed()
        assertTrue(verifies(putPreKeys(), authentication))
        for (index in preKeyBody.indices) {
            val tampered = preKeyBody.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertFalse(verifies(putPreKeys(body = tampered), authentication), "byte $index")
        }
        assertFalse(verifies(putPreKeys(body = preKeyBody + ' '.code.toByte()), authentication), "appended byte")
        assertFalse(verifies(putPreKeys(body = preKeyBody.copyOf(preKeyBody.size - 1)), authentication), "removed byte")
        assertFalse(verifies(putPreKeys(body = ByteArray(0)), authentication), "no body")
    }

    @Test
    fun pathMethodAndAddressAreBound() {
        val authentication = signed()
        val request = putPreKeys()
        val laptop = DeviceAddress(UserId("alice"), DeviceId("laptop"))
        val bob = DeviceAddress(UserId("bob"), DeviceId("phone"))
        assertFalse(verifies(putPreKeys(address = laptop), authentication), "device substituted")
        assertFalse(verifies(putPreKeys(address = bob), authentication), "user substituted")
        assertFalse(verifies(ServerRequest(alice, "GET", request.path, request.body), authentication), "PUT as GET")
        assertFalse(verifies(ServerRequest(alice, "POST", request.path, request.body), authentication), "PUT as POST")
        assertFalse(verifies(ServerRequest(alice, "PUT", ServerApiPaths.device(alice, ServerApiPaths.REGISTRATION), request.body), authentication), "other endpoint")
        // Address fields are bound on their own, not only through the path.
        assertFalse(verifies(ServerRequest(laptop, "PUT", request.path, request.body), authentication), "address field substituted")
        // Length prefixes keep field boundaries apart.
        val shifted = DeviceAddress(UserId("alicep"), DeviceId("hone"))
        assertFalse(verifies(ServerRequest(shifted, "PUT", request.path, request.body), authentication), "boundary shifted")
    }

    @Test
    fun timestampAndNonceAreBound() {
        val authentication = signed()
        val request = putPreKeys()
        val later = RequestAuthentication(timestamp + kotlin.time.Duration.parse("1ms"), authentication.nonce, authentication.signature)
        assertFalse(verifies(request, later), "timestamp")
        val otherNonce = RequestAuthentication(authentication.timestamp, nonce2, authentication.signature)
        assertFalse(verifies(request, otherNonce), "nonce")
    }

    @Test
    fun malformedSignaturesAndKeysDoNotVerify() {
        val authentication = signed()
        val request = putPreKeys()
        val signature = authentication.signature
        for (index in signature.indices) {
            val flipped = signature.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, flipped)), "bit flip at $index")
        }
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, signature.copyOf(63))), "short signature")
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, signature + 0)), "long signature")
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, ByteArray(64))), "zero signature")
        assertFalse(verifies(request, authentication, publicKey.copyOf(31)), "short key")
        assertFalse(verifies(request, authentication, ByteArray(32)), "zero key")
        assertFalse(verifies(ServerRequest(alice, "put", request.path, request.body), authentication), "lower-case method")
        assertFailsWith<IllegalArgumentException> { ServerRequestAuthentication.canonicalInput(ServerRequest(alice, "", "/", ByteArray(0)), timestamp, nonce1) }
    }

    @Test
    fun signaturesFromOtherDomainsDoNotVerify() = runTest {
        val engine = KodiumProtocolEngine()
        val identity = engine.createIdentity()
        val signedPreKey = engine.createSignedPreKey(identity, SignedPreKeyId(1))
        // The Ed25519 half of the identity key, as if someone registered it as a device key.
        val identitySigningKey = identity.publicKey.copyOfRange(32, 64)
        val request = putPreKeys()
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, signedPreKey.signature), identitySigningKey), "signed prekey signature")

        // A signature over the input without the domain does not verify.
        val input = ServerRequestAuthentication.canonicalInput(request, timestamp, nonce1)
        val withoutDomain = input.copyOfRange(4 + "KSecureMessage-ServerAuth-v1".length, input.size)
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, Ed25519.sign(seed, withoutDomain))), "no domain")
        val otherDomain = byteArrayOf(0, 0, 0, 28) + "KSecureMessage-ServerAuth-v2".encodeToByteArray() + withoutDomain
        assertFalse(verifies(request, RequestAuthentication(timestamp, nonce1, Ed25519.sign(seed, otherDomain))), "other domain")
        assertContentEquals(signed().signature, Ed25519.sign(seed, input))
    }

    @Test
    fun valuesAreValidatedAndRedacted() {
        assertFailsWith<IllegalArgumentException> { RequestNonce(ByteArray(15)) }
        assertFailsWith<IllegalArgumentException> { RequestNonce(ByteArray(17)) }
        assertFailsWith<IllegalArgumentException> { RequestAuthentication(Instant.fromEpochMilliseconds(-1), nonce1, ByteArray(64)) }
        assertFailsWith<IllegalArgumentException> {
            RequestAuthentication(Instant.fromEpochSeconds(1, 1), nonce1, ByteArray(64))
        }
        val nonces = List(100) { RequestNonce.random() }
        assertEquals(100, nonces.toSet().size)
        assertEquals(RequestNonce.SIZE, nonces.first().bytes.size)

        val authentication = signed()
        val texts = listOf(keyPair.toString(), nonce1.toString(), authentication.toString(), putPreKeys().toString())
        for (text in texts) {
            assertFalse(text.contains(seed.toHex(), ignoreCase = true), text)
            assertFalse(text.contains(nonce1.bytes.toHex(), ignoreCase = true), text)
            assertFalse(text.contains(authentication.signature.toHex(), ignoreCase = true), text)
            assertFalse(text.contains("identityKey"), text)
        }
    }

    @Test
    fun signingTruncatesToMilliseconds() {
        val authentication = ServerRequestAuthentication.sign(keyPair, get(), Instant.fromEpochSeconds(1_767_225_600, 999_999), nonce1)
        assertEquals(timestamp, authentication.timestamp)
        assertTrue(verifies(get(), authentication))
    }
}
