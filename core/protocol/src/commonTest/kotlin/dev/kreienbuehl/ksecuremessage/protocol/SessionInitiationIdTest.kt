package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import dev.kreienbuehl.ksecuremessage.model.UserId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun key(first: Int) = ByteArray(ProtocolConstants.PUBLIC_KEY_SIZE) { (first + it).toByte() }

/**
 * Frozen vectors: persisted IDs and the simultaneous-initiation decision
 * depend on this construction. Computed independently (Python hashlib) from
 * the layout in docs/session-lifecycle.md.
 */
class SessionInitiationIdTest {
    private val initiator = key(0)
    private val responder = key(64)
    private val ephemeral = key(128)

    private fun id(oneTimePreKeyId: OneTimePreKeyId?, first: ByteArray = initiator, second: ByteArray = responder) =
        SessionInitiationId.derive(first, second, ephemeral, SignedPreKeyId(7), oneTimePreKeyId)

    @Test
    fun matchesVectorWithOneTimePreKey() {
        assertContentEquals(
            hex("745b4451b3e2779db9dd15f4c3ba749abb1543017356b89497ba24ef5ab55ef0"),
            id(OneTimePreKeyId(42)).bytes,
        )
    }

    @Test
    fun matchesVectorWithoutOneTimePreKey() {
        assertContentEquals(
            hex("e2e3a6c8d278e888b5a8d35e75ba090bb98977612b29d2a9d12ecfcf6c621d2a"),
            id(null).bytes,
        )
    }

    @Test
    fun rolesAreBound() {
        assertContentEquals(
            hex("2dc699b7e3b54a776f7339de031c6548e45a2a6ae98154d16d85ad231f978787"),
            id(null, first = responder, second = initiator).bytes,
        )
    }

    @Test
    fun messageIdMatchesDerivation() {
        val message = PreKeyMessage(initiator, ephemeral, SignedPreKeyId(7), OneTimePreKeyId(42), RatchetMessage(byteArrayOf(1)), SessionInitiationVersion.V1)
        assertEquals(id(OneTimePreKeyId(42)), SessionInitiationId.of(message, responder))
    }

    @Test
    fun domainIsUnchanged() {
        assertEquals("KSecureMessage-SessionInitiation-v1", ProtocolConstants.SESSION_INITIATION_DOMAIN)
    }

    // Session initiation v2 (S1, findings F3/F4). Computed independently with
    // Python hashlib from the transcript layout in docs/session-lifecycle.md;
    // never regenerate them with the implementation.

    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))
    private val bob = DeviceAddress(UserId("bob"), DeviceId("laptop"))

    private fun v2(
        sender: DeviceAddress = alice,
        recipient: DeviceAddress = bob,
        ephemeralKey: ByteArray = ephemeral,
        signedPreKeyId: Int = 7,
        oneTimePreKeyId: Int? = 42,
    ) = SessionInitiationId.v2Of(
        PreKeyMessage(
            initiator,
            ephemeralKey,
            SignedPreKeyId(signedPreKeyId),
            oneTimePreKeyId?.let(::OneTimePreKeyId),
            RatchetMessage(byteArrayOf(1)),
            SessionInitiationVersion.V2,
        ),
        sender,
        recipient,
        responder,
    )

    @Test
    fun v2TranscriptMatchesLayout() {
        val transcript = SessionInitiationId.v2Transcript(alice, bob, initiator, responder, ephemeral, SignedPreKeyId(7), OneTimePreKeyId(42))
        assertEquals(275, transcript.size)
        assertContentEquals(
            hex(
                "00000023" + "4b5365637572654d6573736167652d53657373696f6e496e6974696174696f6e2d7632" +
                    "00000005616c696365" + "0000000570686f6e65" + "00000003626f62" + "000000066c6170746f70" + "000102030405",
            ),
            transcript.copyOfRange(0, 80),
        )
    }

    @Test
    fun v2MatchesVectorWithOneTimePreKey() {
        assertContentEquals(hex("bf2652d951b7e88528d33487d1ebd62a9fef89be9b6562d93d402d9fa36d4d25"), v2().bytes)
    }

    @Test
    fun v2MatchesVectorWithoutOneTimePreKey() {
        assertContentEquals(hex("e90755241ce06da6910496bd5497dccf0b72b70c29ad66a28a62b28785529313"), v2(oneTimePreKeyId = null).bytes)
    }

    @Test
    fun v2BindsTheAddressesAndTheirDirection() {
        assertContentEquals(hex("deb09908a5457c999a61145e1f5b2b094abb121c18fcb62887cc9f05a369a01f"), v2(sender = bob, recipient = alice).bytes)
        // Length prefixes: moving a character across the user/device boundary changes the ID.
        assertContentEquals(
            hex("e49703941e0a5e9bb44c1f0b906e2fd5ab338878515d64f5dce9dd5932973d4d"),
            v2(sender = DeviceAddress(UserId("alicep"), DeviceId("hone"))).bytes,
        )
    }

    @Test
    fun v2EncodesAddressesAsUtf8() {
        assertContentEquals(
            hex("66fcab87b73fed898433d135eba6fb8018c6aad7ffae23c5b57bcd4f49641d81"),
            v2(sender = DeviceAddress(UserId("zoë"), DeviceId("📱")), recipient = DeviceAddress(UserId("Бob"), DeviceId("lap top/1"))).bytes,
        )
    }

    @Test
    fun v2BindsEveryHeaderField() {
        val mutatedSigningHalf = ephemeral.copyOf().also { it[63] = (it[63].toInt() xor 1).toByte() }
        assertContentEquals(hex("1121af27825660ca7ce6bc57419a6391fa473cf5335d9a39c03f8bc572b3a708"), v2(ephemeralKey = mutatedSigningHalf).bytes)
        assertContentEquals(hex("48ef41b47ba46b6673316956247f74257fd668b542df670c7781501132750e6c"), v2(signedPreKeyId = 8).bytes)
        assertContentEquals(hex("cc2b7af9150dd72b7536decf465e3ea1712d64632e139a5b1f7013a683c1bcf3"), v2(oneTimePreKeyId = 43).bytes)
    }

    @Test
    fun v2IsTheSha256OfTheTranscriptAndDisjointFromV1() {
        val transcript = SessionInitiationId.v2Transcript(alice, bob, initiator, responder, ephemeral, SignedPreKeyId(7), OneTimePreKeyId(42))
        assertEquals(v2(), SessionInitiationId.ofTranscript(transcript))
        assertNotEquals(id(OneTimePreKeyId(42)), v2(), "another domain")
        assertEquals("KSecureMessage-SessionInitiation-v2", ProtocolConstants.SESSION_INITIATION_V2_DOMAIN)
    }

    @Test
    fun v2RefusesAVersion1Message() {
        val message = PreKeyMessage(initiator, ephemeral, SignedPreKeyId(7), null, RatchetMessage(byteArrayOf(1)), SessionInitiationVersion.V1)
        assertFailsWith<ProtocolException.InvalidMessage> { SessionInitiationId.v2Of(message, alice, bob, responder) }
    }

    @Test
    fun orderIsUnsignedLexicographic() {
        val low = SessionInitiationId(ByteArray(32).also { it[0] = 0x7F })
        val high = SessionInitiationId(ByteArray(32).also { it[0] = 0x80.toByte() })
        val last = SessionInitiationId(ByteArray(32).also { it[31] = 1 })
        assertTrue(low < high, "0x80 sorts after 0x7F")
        assertTrue(SessionInitiationId(ByteArray(32)) < last)
        assertEquals(0, low.compareTo(SessionInitiationId(low.bytes)))
        assertEquals(low, SessionInitiationId(low.bytes))
        assertNotEquals(low, high)
    }

    @Test
    fun bytesAreCopied() {
        val source = ByteArray(32)
        val id = SessionInitiationId(source)
        source[0] = 1
        id.bytes[0] = 2
        assertContentEquals(ByteArray(32), id.bytes)
        assertEquals("SessionInitiationId(<redacted>)", id.toString())
    }

    @Test
    fun invalidInputIsRejected() {
        assertFailsWith<IllegalArgumentException> { SessionInitiationId(ByteArray(31)) }
        assertFailsWith<ProtocolException.InvalidMessage> {
            SessionInitiationId.derive(ByteArray(63), responder, ephemeral, SignedPreKeyId(7), null)
        }
    }
}
