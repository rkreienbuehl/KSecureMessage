package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
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
 * Frozen vectors of last-device recovery format version 1
 * (docs/last-device-recovery.md). Every recovery key a server registered and
 * every recovery it accepted depend on them. Computed independently (Python
 * struct, hashlib, base64 and the `cryptography` package's Ed25519) from the
 * documented layout; the same script first reproduced the frozen routine
 * rotation vectors.
 */
class LastDeviceRecoveryTest {
    private fun keyPair(first: Int, publicKey: String) =
        DeviceAuthenticationKeyPair(hex(publicKey), ByteArray(32) { (first + it).toByte() })

    private val key1 = keyPair(0x40, "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")
    private val key2 = keyPair(0x60, "174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5")
    private val key3 = keyPair(0x80, "cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa")

    private val recoverySeed = ByteArray(32) { (0xC0 + it).toByte() }
    private val recoveryKey = LastDeviceRecoveryKey.fromSeed(recoverySeed)
    private val recoveryPublicKey = "dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8"
    private val recoveryText = "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8"

    private val phone = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val tablet = DeviceAddress(UserId("alice"), DeviceId("tablet"))
    private val encoded = DeviceAddress(UserId("ä b/c"), DeviceId("dev~1"))
    private val challengeId1 = LastDeviceRecoveryChallengeId(ByteArray(16) { (0x10 + it).toByte() })
    private val challengeId2 = LastDeviceRecoveryChallengeId(ByteArray(16) { (0xF0 + it).toByte() })
    private val nonce1 = ByteArray(32) { (0x20 + it).toByte() }
    private val nonce2 = ByteArray(32) { (0xFF - it).toByte() }
    private val expiresAt = Instant.fromEpochMilliseconds(1_767_225_900_000)

    private fun base(
        target: DeviceAddress = phone,
        challengeId: LastDeviceRecoveryChallengeId = challengeId1,
        nonce: ByteArray = nonce1,
        epoch: Long = 7,
        replacement: DeviceAuthenticationKeyPair = key2,
    ): Pair<LastDeviceRecoveryChallenge, DeviceAuthenticationKeyPair> =
        LastDeviceRecoveryChallenge(target, challengeId, nonce, epoch, expiresAt) to replacement

    private class Vector(
        val case: Pair<LastDeviceRecoveryChallenge, DeviceAuthenticationKeyPair>,
        val authorizationInput: String,
        val proofOfPossessionInput: String,
        val recoveryId: String,
        val recoverySignature: String,
        val proofOfPossession: String,
    )

    private fun Vector.authorization() = LastDeviceRecovery.authorize(recoveryKey, case.second, case.first)

    private val vectors by lazy {
        mapOf(
            "base" to Vector(
                base(),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000057068" +
                    "6f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f20212223" +
                    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddfc6908eca" +
                    "b1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddf" +
                    "c6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "b4e550c4c7f4ad71b4bb04295a5bfd62e4fbcd486ea69560961fb8ffb9dae14d",
                "4348b15342e9d10109116ce42b0c209fe8cfd0ddf9026a6a389c11a8ee82e17b6dcc519d6ba7cd6d44dcae725e2ff8de9f1e09f7f7112d" +
                    "e9dc7fbabebd546e04",
                "b69abc4ef893904139594e2eea9558df96bd9974dd013706f71760eb9a07edf78114d8f7daa8b4d8dd9768148f7d7f6a7268d013ed5123" +
                    "c74d97b1668d693d08",
            ),
            "other target" to Vector(
                base(target = tablet),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000067461" +
                    "626c6574dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f202122" +
                    "232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddfc6908e" +
                    "cab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "00067461626c6574dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e" +
                    "1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dd" +
                    "dfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "92afb43f03a4c5b69192525ddffda34d505bd0e967e370e4be9fcb413fc6ac99",
                "59158ea1d0bb526b0875fb4183455a93db8721392778f483c15b66619c03d220bd10f4dcab7e011776cd33cdcd38dd0bc7d60a7168d8cf" +
                    "4ccbcdea35153b120f",
                "f25d0ffa53944269f7e69e6ea921103696e56258ec75a80e572ad39df75eac468d734d085b680a01ace9fd3ce1e948965494285b0499b8" +
                    "22d52cdcfb1a258b05",
            ),
            "other epoch" to Vector(
                base(epoch = 8),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000057068" +
                    "6f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f20212223" +
                    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000080000019b76df3be0174553b456dddfc6908eca" +
                    "b1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000080000019b76df3be0174553b456dddf" +
                    "c6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "2c4830928858e01e3cf7d201e3e0acac1fd75320aa95bf3ee55a870633a343ba",
                "c20cd416f3961b8b52d9704929274a8f25b416504a0d5a641a3f01bc65e3c1f82fc9a5341df2f8f61bba85b53c950768b680f2160e14cd" +
                    "de1a9513187a5fd308",
                "04403e310a26d2617b175f45a644e692e24fe73525960e9c75298947748f0de7082efeb20902334e79e886e4e6e0b665839a318cedb9c1" +
                    "3a92cd4a3738251101",
            ),
            "other challenge id" to Vector(
                base(challengeId = challengeId2),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000057068" +
                    "6f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff20212223" +
                    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddfc6908eca" +
                    "b1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddf" +
                    "c6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "b47171298d6e58de1b8966d959791ecc67d7c085c9cabeb289cc50dc9db87906",
                "5c03408a248388ffa534270fa7a2b42bdec178195ad29716cf08cd612e66d13248dd23dda375a8dc0fc90d3b6d4b82278a474710b5670b" +
                    "fc7b67bb64df3da805",
                "4f627a62eba38607748469cec0f9e025e097c01696b9a408803c6b1b725d71464cfd82111f288842f3016fce3f84272ba53e74ccd4dc81" +
                    "18ac751cd5c72d170c",
            ),
            "other challenge nonce" to Vector(
                base(nonce = nonce2),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000057068" +
                    "6f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1ffffefdfc" +
                    "fbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000000000000000070000019b76df3be0174553b456dddfc6908eca" +
                    "b1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f" +
                    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000000000000000070000019b76df3be0174553b456dddf" +
                    "c6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "0a269f885d03008f95c4c5e74db8c87183bd32565d61c20962b26249da7da849",
                "1a90d0b3412b340bedc2ee3cf5f00c37b837c6c46834489f1d7961b44522c789f0c4b6a489254cba84f8af483db1f257602050f7f51e76" +
                    "72d8019100b6fc7c06",
                "0ecdc7bad719b68534560cfbaa6611f4721e6396e7a2c8a5ada6c436900291fa1e958f60cec000b6dbb91a6a37ab9daf18fb3d40131e69" +
                    "d1822bf0cc39fa4c0d",
            ),
            "other replacement" to Vector(
                base(replacement = key3),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000005616c696365000000057068" +
                    "6f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f20212223" +
                    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0cd14b37f956e953194ff7f" +
                    "b73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000005616c6963650000" +
                    "000570686f6e65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f" +
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0cd14b37f956e95" +
                    "3194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa",
                "b7c659f920c6d19af68d38859137dc2aa5fc1f8d554cdf5c60fe53e513ff53c7",
                "49ee6898c3ea75b92c3dadd4636695e04341930458739e98f82cedb1559130e60d9cfb7b0fff8cdf26a8d16a89c26fc921ce049e1cc710" +
                    "8b6d521336eb714f06",
                "04e9b918492061702a16b7623685ab1b40f9e837febd28a3094230bc22fffe58e506f29d27c0d01cb50ed1a866ace62f669ea6da011f90" +
                    "fb83c508a501f28704",
            ),
            "utf8 address" to Vector(
                base(target = encoded),
                "000000244b5365637572654d6573736167652d4c6173744465766963655265636f766572792d763100000006c3a420622f630000000564" +
                    "65767e31dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e1f202122" +
                    "232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dddfc6908e" +
                    "cab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "000000284b5365637572654d6573736167652d4c6173744465766963655265636f766572792d506f502d763100000006c3a420622f6300" +
                    "0000056465767e31dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8101112131415161718191a1b1c1d1e" +
                    "1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000070000019b76df3be0174553b456dd" +
                    "dfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5",
                "2da22be234c331d5ef2cabf962c88a80ba6d5dc1758f6ee96e23ffbc395fc35d",
                "f7cbece5414727731036c89f60e2f3f4195f16ea56bdf8bc2eb22a2114740245f843ead7f57b458cbb97f787aee2fe8d0d847695d6faab" +
                    "95b6782efcee57c90f",
                "0bf00accd2b9a9a3ea22524b939018ada0749a9779d0d467ee82ac43c30d68521629d55b838cfa7a4e906e42fb7097bad40ff1797b0748" +
                    "d24edcac627884aa08",
            ),
        )
    }

    @Test
    fun recoveryKeyMatchesItsSeedAndTextForm() {
        assertEquals(recoveryPublicKey, recoveryKey.publicKey.toHex())
        assertEquals(recoveryText, recoveryKey.encode())
        assertEquals(recoveryKey, LastDeviceRecoveryKey.decode(recoveryText))
        assertEquals(recoveryPublicKey, LastDeviceRecoveryKey.decode(recoveryText).publicKey.toHex())
        assertEquals(key2.publicKey.toHex(), Ed25519.publicKey(key2.privateKey).toHex())
        assertEquals(key3.publicKey.toHex(), Ed25519.publicKey(key3.privateKey).toHex())
    }

    @Test
    fun generatedKeysRoundTripThroughTheirTextForm() = runTest {
        val engine = KodiumProtocolEngine()
        val first = engine.createLastDeviceRecoveryKey()
        val second = engine.createLastDeviceRecoveryKey()
        assertNotEquals(first, second)
        val text = first.encode()
        assertEquals(LastDeviceRecoveryKey.TEXT_LENGTH, text.length)
        val decoded = LastDeviceRecoveryKey.decode(text)
        assertEquals(first, decoded)
        assertEquals(text, decoded.encode())
        val registration = LastDeviceRecovery.registerKey(decoded, UserId("alice"))
        assertContentEquals(first.publicKey, registration.publicKey)
        assertTrue(LastDeviceRecovery.verifyKeyRegistration(registration))
    }

    @Test
    fun textDecodingIsStrict() {
        val rejected = listOf(
            "",
            recoveryText.dropLast(1),
            recoveryText + "A",
            "$recoveryText=",
            " $recoveryText",
            "$recoveryText ",
            recoveryText.substring(0, 20) + " " + recoveryText.substring(21),
            recoveryText.substring(0, 20) + "\n" + recoveryText.substring(21),
            // Standard Base64 alphabet characters.
            recoveryText.substring(0, 10) + "/" + recoveryText.substring(11),
            recoveryText.substring(0, 10) + "+" + recoveryText.substring(11),
            // Same bytes, non-zero padding bits in the last character: not canonical.
            recoveryText.dropLast(1) + "9",
            recoveryText.dropLast(1) + "u",
            recoveryText.substring(0, 42) + "!",
        )
        for (text in rejected) {
            assertFailsWith<IllegalArgumentException>(text) { LastDeviceRecoveryKey.decode(text) }
        }
        assertEquals(recoveryKey, LastDeviceRecoveryKey.decode(recoveryText))
    }

    @Test
    fun toStringNeverPrintsKeyMaterial() {
        val authorization = vectors.getValue("base").authorization()
        val statement = authorization.statement
        val registration = LastDeviceRecovery.registerKey(recoveryKey, UserId("alice"))
        val texts = listOf(
            recoveryKey.toString(),
            authorization.toString(),
            statement.toString(),
            statement.challenge.toString(),
            statement.challenge.id.toString(),
            LastDeviceRecovery.recoveryId(statement).toString(),
            registration.toString(),
        )
        for (text in texts) {
            assertFalse(recoveryText in text, text)
            assertFalse(recoveryPublicKey in text.lowercase(), text)
            assertFalse(recoverySeed.toHex() in text.lowercase(), text)
        }
        assertEquals("LastDeviceRecoveryKey(<redacted>)", recoveryKey.toString())
    }

    @Test
    fun recoveryInputsAreFrozen() {
        for ((name, vector) in vectors) {
            val statement = vector.authorization().statement
            assertEquals(vector.authorizationInput, LastDeviceRecovery.authorizationInput(statement).toHex(), name)
            assertEquals(vector.proofOfPossessionInput, LastDeviceRecovery.proofOfPossessionInput(statement).toHex(), name)
        }
    }

    @Test
    fun recoveryIdsAreFrozen() {
        for ((name, vector) in vectors) {
            assertEquals(vector.recoveryId, LastDeviceRecovery.recoveryId(vector.authorization().statement).bytes.toHex(), name)
        }
        assertEquals(vectors.size, vectors.values.map { it.recoveryId }.toSet().size)
    }

    @Test
    fun signaturesAreFrozen() {
        for ((name, vector) in vectors) {
            val authorization = vector.authorization()
            assertEquals(vector.recoverySignature, authorization.recoverySignature.toHex(), name)
            assertEquals(vector.proofOfPossession, authorization.proofOfPossession.toHex(), name)
        }
    }

    @Test
    fun frozenSignaturesVerify() {
        for ((name, vector) in vectors) {
            val authorization = LastDeviceRecoveryAuthorization(
                vector.authorization().statement,
                hex(vector.recoverySignature),
                hex(vector.proofOfPossession),
            )
            assertTrue(LastDeviceRecovery.verifyRecoverySignature(hex(recoveryPublicKey), authorization), name)
            assertTrue(LastDeviceRecovery.verifyProofOfPossession(authorization), name)
        }
    }

    @Test
    fun keyRegistrationIsFrozen() {
        val cases = listOf(
            Triple(
                "alice",
                "0000002b4b5365637572654d6573736167652d4c6173744465766963655265636f766572794b65792d506f502d763100000005616c6963" +
                    "65dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8",
                "6a185d9387627c697edf6a450e8166dcb0008bfaaaec0175e01909f5814ab0b03809ee66b7d6fd518fe212bec5a2a06b60a0ffbcb4f7b2" +
                    "6496348001bce1bd07",
            ),
            Triple(
                "ä b/c",
                "0000002b4b5365637572654d6573736167652d4c6173744465766963655265636f766572794b65792d506f502d763100000006c3a42062" +
                    "2f63dde3bccec7f3a66a1115f45d720f4dc135c3ae7c4e22dca38fdb1efd6a495ff8",
                "d941c222a21e8d161ea25fe90f35862dbfba71284878ef870ef1d63cb9dd4cb54861ba9ee62c610b58ed46531b16a171fdd654b6f34068" +
                    "862060704fc389870d",
            )
        )
        for ((user, input, signature) in cases) {
            assertEquals(input, LastDeviceRecovery.keyRegistrationInput(UserId(user), hex(recoveryPublicKey)).toHex(), user)
            val registration = LastDeviceRecovery.registerKey(recoveryKey, UserId(user))
            assertEquals(signature, registration.proofOfPossession.toHex(), user)
            assertTrue(LastDeviceRecovery.verifyKeyRegistration(registration), user)
        }
    }

    @Test
    fun keyRegistrationIsBoundToUserAndKey() {
        val registration = LastDeviceRecovery.registerKey(recoveryKey, UserId("alice"))
        assertFalse(
            LastDeviceRecovery.verifyKeyRegistration(
                LastDeviceRecoveryKeyRegistration(UserId("bob"), registration.publicKey, registration.proofOfPossession),
            ),
        )
        assertFalse(
            LastDeviceRecovery.verifyKeyRegistration(
                LastDeviceRecoveryKeyRegistration(UserId("alice"), key2.publicKey, registration.proofOfPossession),
            ),
        )
        val tampered = registration.proofOfPossession.also { it[0] = (it[0] + 1).toByte() }
        assertFalse(
            LastDeviceRecovery.verifyKeyRegistration(
                LastDeviceRecoveryKeyRegistration(UserId("alice"), registration.publicKey, tampered),
            ),
        )
    }

    @Test
    fun everyFieldIsBoundByBothSignatures() {
        val authorization = vectors.getValue("base").authorization()
        val statement = authorization.statement
        val challenge = statement.challenge
        val swapped = listOf(
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(tablet, challenge.id, challenge.nonce, challenge.authEpoch, challenge.expiresAt),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(DeviceAddress(UserId("bob"), DeviceId("phone")), challenge.id, challenge.nonce, challenge.authEpoch, challenge.expiresAt),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(phone, challengeId2, challenge.nonce, challenge.authEpoch, challenge.expiresAt),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(phone, challenge.id, nonce2, challenge.authEpoch, challenge.expiresAt),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(phone, challenge.id, challenge.nonce, 8, challenge.expiresAt),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(
                LastDeviceRecoveryChallenge(phone, challenge.id, challenge.nonce, challenge.authEpoch, Instant.fromEpochMilliseconds(1_767_225_900_001)),
                statement.recoveryPublicKey,
                statement.replacementPublicKey,
            ),
            LastDeviceRecoveryStatement(challenge, key1.publicKey, statement.replacementPublicKey),
            LastDeviceRecoveryStatement(challenge, statement.recoveryPublicKey, key3.publicKey),
        )
        for (other in swapped) {
            val forged = LastDeviceRecoveryAuthorization(other, authorization.recoverySignature, authorization.proofOfPossession)
            assertFalse(
                LastDeviceRecovery.verifyRecoverySignature(recoveryKey.publicKey, forged) &&
                    LastDeviceRecovery.verifyProofOfPossession(forged),
                other.toString(),
            )
            assertNotEquals(LastDeviceRecovery.recoveryId(statement), LastDeviceRecovery.recoveryId(other))
        }
    }

    @Test
    fun wrongKeysAndMalformedSignaturesDoNotVerify() {
        val authorization = vectors.getValue("base").authorization()
        assertFalse(LastDeviceRecovery.verifyRecoverySignature(key1.publicKey, authorization))
        assertFalse(LastDeviceRecovery.verifyRecoverySignature(key2.publicKey, authorization))
        assertFalse(LastDeviceRecovery.verifyRecoverySignature(ByteArray(31), authorization))
        val swapped = LastDeviceRecoveryAuthorization(authorization.statement, authorization.proofOfPossession, authorization.recoverySignature)
        assertFalse(LastDeviceRecovery.verifyRecoverySignature(recoveryKey.publicKey, swapped))
        assertFalse(LastDeviceRecovery.verifyProofOfPossession(swapped))
        val flipped = authorization.recoverySignature.also { it[63] = (it[63].toInt() xor 1).toByte() }
        assertFalse(
            LastDeviceRecovery.verifyRecoverySignature(
                recoveryKey.publicKey,
                LastDeviceRecoveryAuthorization(authorization.statement, flipped, authorization.proofOfPossession),
            ),
        )
    }

    @Test
    fun domainsAreDistinctFromEveryOtherSignature() {
        val authorization = vectors.getValue("base").authorization()
        val statement = authorization.statement
        val inputs = listOf(
            LastDeviceRecovery.authorizationInput(statement),
            LastDeviceRecovery.proofOfPossessionInput(statement),
            LastDeviceRecovery.keyRegistrationInput(UserId("alice"), recoveryKey.publicKey),
        )
        assertEquals(inputs.size, inputs.map { it.toHex() }.toSet().size)
        // A recovery-key signature never verifies as a signature of another protocol, and the other way round.
        val recoveryAsKeyPair = DeviceAuthenticationKeyPair(recoveryKey.publicKey, recoverySeed)
        val rotation = DeviceAuthenticationRotation.create(recoveryAsKeyPair, key2, phone, 7, Instant.fromEpochMilliseconds(1_767_225_600_000), RequestNonce(ByteArray(16)))
        val deviceRecovery = DeviceRecovery.prepare(key2, phone, tablet, Instant.fromEpochMilliseconds(1_767_225_600_000), RequestNonce(ByteArray(16)))
        val serverRequest = ServerRequest(phone, "PUT", ServerApiPaths.device(phone, ServerApiPaths.LAST_DEVICE_RECOVERY), LastDeviceRecovery.authorizationInput(statement))
        val serverAuth = ServerRequestAuthentication.sign(recoveryAsKeyPair, serverRequest, Instant.fromEpochMilliseconds(1_767_225_600_000), RequestNonce(ByteArray(16)))
        val foreign = listOf(rotation.authorizationSignature, rotation.proofOfPossession, deviceRecovery.proofOfPossession, serverAuth.signature)
        for (signature in foreign) {
            val forged = LastDeviceRecoveryAuthorization(statement, signature, signature)
            assertFalse(LastDeviceRecovery.verifyRecoverySignature(recoveryKey.publicKey, forged))
            assertFalse(LastDeviceRecovery.verifyProofOfPossession(forged))
        }
        assertFalse(DeviceAuthenticationRotation.verifyAuthorization(recoveryKey.publicKey, DeviceAuthenticationRotationAuthorization(rotation.statement, authorization.recoverySignature, authorization.proofOfPossession)))
        assertFalse(DeviceAuthenticationRotation.verifyProofOfPossession(DeviceAuthenticationRotationAuthorization(rotation.statement, authorization.proofOfPossession, authorization.proofOfPossession)))
        assertFalse(DeviceRecovery.verifyProofOfPossession(DeviceRecoveryRequest(phone, tablet, key2.publicKey, deviceRecovery.timestamp, deviceRecovery.nonce, authorization.proofOfPossession)))
        assertFalse(ServerRequestAuthentication.verify(recoveryKey.publicKey, serverRequest, RequestAuthentication(serverAuth.timestamp, serverAuth.nonce, authorization.recoverySignature)))
        for (domain in listOf(
            ProtocolConstants.LAST_DEVICE_RECOVERY_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_POP_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_ID_DOMAIN,
            ProtocolConstants.LAST_DEVICE_RECOVERY_KEY_POP_DOMAIN,
        )) {
            assertFalse(
                domain in setOf(
                    ProtocolConstants.SERVER_AUTH_DOMAIN,
                    ProtocolConstants.DEVICE_RECOVERY_DOMAIN,
                    ProtocolConstants.DEVICE_RECOVERY_POP_DOMAIN,
                    ProtocolConstants.DEVICE_RECOVERY_ID_DOMAIN,
                    ProtocolConstants.DEVICE_AUTH_ROTATION_DOMAIN,
                    ProtocolConstants.DEVICE_AUTH_ROTATION_POP_DOMAIN,
                    ProtocolConstants.DEVICE_AUTH_ROTATION_ID_DOMAIN,
                    ProtocolConstants.SAFETY_NUMBER_DOMAIN,
                    ProtocolConstants.RECOVERY_KEY_RESET_NEW_KEY_POP_DOMAIN,
                    ProtocolConstants.RECOVERY_KEY_RESET_ID_DOMAIN,
                    ProtocolConstants.RECOVERY_KEY_RESET_CANCEL_DOMAIN,
                    ProtocolConstants.RECOVERY_KEY_RESET_STATUS_QUERY_DOMAIN,
                ),
            )
        }
    }

    @Test
    fun invalidValuesAreRejected() {
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryChallengeId(ByteArray(15)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryChallenge(phone, challengeId1, ByteArray(31), 7, expiresAt) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryChallenge(phone, challengeId1, nonce1, 0, expiresAt) }
        assertFailsWith<IllegalArgumentException> {
            LastDeviceRecoveryChallenge(phone, challengeId1, nonce1, 7, Instant.fromEpochMilliseconds(-1))
        }
        assertFailsWith<IllegalArgumentException> {
            LastDeviceRecoveryChallenge(phone, challengeId1, nonce1, 7, Instant.fromEpochSeconds(1_767_225_900, 1))
        }
        val challenge = LastDeviceRecoveryChallenge(phone, challengeId1, nonce1, 7, expiresAt)
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryStatement(challenge, ByteArray(31), key2.publicKey) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryStatement(challenge, recoveryKey.publicKey, ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryStatement(challenge, recoveryKey.publicKey, recoveryKey.publicKey) }
        val statement = LastDeviceRecoveryStatement(challenge, recoveryKey.publicKey, key2.publicKey)
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryAuthorization(statement, ByteArray(63), ByteArray(64)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryAuthorization(statement, ByteArray(64), ByteArray(65)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryId(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryKeyRegistration(UserId("alice"), ByteArray(31), ByteArray(64)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryKeyRegistration(UserId("alice"), ByteArray(32), ByteArray(63)) }
        assertFailsWith<IllegalArgumentException> { LastDeviceRecoveryKey.fromSeed(ByteArray(31)) }
    }

    @Test
    fun valuesAreDefensivelyCopied() {
        val nonce = nonce1.copyOf()
        val challenge = LastDeviceRecoveryChallenge(phone, challengeId1, nonce, 7, expiresAt)
        nonce.fill(0)
        challenge.nonce.fill(0)
        assertContentEquals(nonce1, challenge.nonce)
        val publicKey = recoveryKey.publicKey
        publicKey.fill(0)
        assertEquals(recoveryPublicKey, recoveryKey.publicKey.toHex())
    }
}
