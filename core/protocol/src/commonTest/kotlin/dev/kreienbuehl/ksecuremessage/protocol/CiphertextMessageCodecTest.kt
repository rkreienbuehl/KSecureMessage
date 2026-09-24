package dev.kreienbuehl.ksecuremessage.protocol

import dev.kreienbuehl.ksecuremessage.model.CiphertextMessage
import dev.kreienbuehl.ksecuremessage.model.OneTimePreKeyId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.RatchetMessage
import dev.kreienbuehl.ksecuremessage.model.SignedPreKeyId
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

private fun hex(value: String): ByteArray =
    ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

private fun key(fill: Int) = ByteArray(ProtocolConstants.PUBLIC_KEY_SIZE) { fill.toByte() }

private fun preKeyMessage(
    signedPreKeyId: Int = 7,
    oneTimePreKeyId: Int? = 42,
    identityKey: ByteArray = key(0x11),
    ephemeralKey: ByteArray = key(0x22),
    ratchet: ByteArray = hex("cafe"),
) = PreKeyMessage(
    identityKey = identityKey,
    ephemeralKey = ephemeralKey,
    signedPreKeyId = SignedPreKeyId(signedPreKeyId),
    oneTimePreKeyId = oneTimePreKeyId?.let(::OneTimePreKeyId),
    message = RatchetMessage(ratchet),
)

private fun assertPreKeyMessageEquals(expected: PreKeyMessage, actual: CiphertextMessage) {
    val message = assertIs<PreKeyMessage>(actual)
    assertContentEquals(expected.identityKey, message.identityKey)
    assertContentEquals(expected.ephemeralKey, message.ephemeralKey)
    assertEquals(expected.signedPreKeyId, message.signedPreKeyId)
    assertEquals(expected.oneTimePreKeyId, message.oneTimePreKeyId)
    assertContentEquals(expected.message.bytes, message.message.bytes)
}

class CiphertextMessageCodecTest {
    // Version-1 compatibility vectors. Written out by hand from
    // docs/wire-format.md; never regenerate them with the codec.
    private val ratchetVector = hex("0101" + "00000004" + "deadbeef")

    private val preKeyVectorWithOneTimePreKey = hex(
        "0102" + "00000007" + "01" + "0000002a"
            + "1111111111111111111111111111111111111111111111111111111111111111"
            + "1111111111111111111111111111111111111111111111111111111111111111"
            + "2222222222222222222222222222222222222222222222222222222222222222"
            + "2222222222222222222222222222222222222222222222222222222222222222"
            + "00000002" + "cafe",
    )

    private val preKeyVectorWithoutOneTimePreKey = hex(
        "0102" + "01020304" + "00"
            + "1111111111111111111111111111111111111111111111111111111111111111"
            + "1111111111111111111111111111111111111111111111111111111111111111"
            + "2222222222222222222222222222222222222222222222222222222222222222"
            + "2222222222222222222222222222222222222222222222222222222222222222"
            + "00000003" + "abcdef",
    )

    private inline fun <reified T : ProtocolException> assertRejected(bytes: ByteArray) {
        assertFailsWith<T> { CiphertextMessageCodec.decode(bytes) }
    }

    // RatchetMessage

    @Test
    fun ratchetMessageMatchesVector() {
        assertContentEquals(ratchetVector, CiphertextMessageCodec.encode(RatchetMessage(hex("deadbeef"))))
        val decoded = assertIs<RatchetMessage>(CiphertextMessageCodec.decode(ratchetVector))
        assertContentEquals(hex("deadbeef"), decoded.bytes)
    }

    @Test
    fun ratchetMessageRoundTripIsDeterministic() {
        val message = RatchetMessage(ByteArray(300) { it.toByte() })
        val first = CiphertextMessageCodec.encode(message)
        assertContentEquals(first, CiphertextMessageCodec.encode(RatchetMessage(message.bytes.copyOf())))
        assertContentEquals(message.bytes, assertIs<RatchetMessage>(CiphertextMessageCodec.decode(first)).bytes)
        assertContentEquals(first, CiphertextMessageCodec.encode(CiphertextMessageCodec.decode(first)))
    }

    @Test
    fun emptyRatchetPayloadIsRejected() {
        assertFailsWith<ProtocolException.MalformedMessage> { CiphertextMessageCodec.encode(RatchetMessage(ByteArray(0))) }
        assertRejected<ProtocolException.MalformedMessage>(hex("0101" + "00000000"))
    }

    @Test
    fun truncatedRatchetMessageIsRejected() {
        for (size in 0 until ratchetVector.size) {
            assertFailsWith<ProtocolException> { CiphertextMessageCodec.decode(ratchetVector.copyOf(size)) }
        }
        assertRejected<ProtocolException.MalformedMessage>(hex("0101" + "000000"))
    }

    @Test
    fun declaredLengthLargerThanDataIsRejected() {
        assertRejected<ProtocolException.MalformedMessage>(hex("0101" + "00000005" + "deadbeef"))
    }

    @Test
    fun oversizedRatchetLengthIsRejectedWithoutAllocating() {
        // The declared lengths are far beyond the input; the decoder must
        // reject them from the length field alone.
        assertRejected<ProtocolException.MessageTooLarge>(hex("0101" + "00040001" + "00"))
        assertRejected<ProtocolException.MessageTooLarge>(hex("0101" + "7fffffff" + "00"))
        assertRejected<ProtocolException.MessageTooLarge>(hex("0101" + "ffffffff" + "00"))
    }

    @Test
    fun maximumRatchetPayloadIsAccepted() {
        val message = RatchetMessage(ByteArray(CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE) { 1 })
        val encoded = CiphertextMessageCodec.encode(message)
        assertEquals(message.bytes.size, assertIs<RatchetMessage>(CiphertextMessageCodec.decode(encoded)).bytes.size)
    }

    @Test
    fun oversizedRatchetPayloadIsRejected() {
        val tooLarge = RatchetMessage(ByteArray(CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE + 1))
        assertFailsWith<ProtocolException.MessageTooLarge> { CiphertextMessageCodec.encode(tooLarge) }
        assertRejected<ProtocolException.MessageTooLarge>(ByteArray(CiphertextMessageCodec.MAX_ENCODED_SIZE + 1))
    }

    @Test
    fun ratchetMessageWithTrailingBytesIsRejected() {
        assertRejected<ProtocolException.MalformedMessage>(ratchetVector + byteArrayOf(0))
    }

    // PreKeyMessage

    @Test
    fun preKeyMessageWithOneTimePreKeyMatchesVector() {
        val message = preKeyMessage()
        assertContentEquals(preKeyVectorWithOneTimePreKey, CiphertextMessageCodec.encode(message))
        assertPreKeyMessageEquals(message, CiphertextMessageCodec.decode(preKeyVectorWithOneTimePreKey))
    }

    @Test
    fun preKeyMessageWithoutOneTimePreKeyMatchesVector() {
        val message = preKeyMessage(signedPreKeyId = 0x01020304, oneTimePreKeyId = null, ratchet = hex("abcdef"))
        assertContentEquals(preKeyVectorWithoutOneTimePreKey, CiphertextMessageCodec.encode(message))
        val decoded = CiphertextMessageCodec.decode(preKeyVectorWithoutOneTimePreKey)
        assertPreKeyMessageEquals(message, decoded)
        assertNull(assertIs<PreKeyMessage>(decoded).oneTimePreKeyId)
    }

    @Test
    fun preKeyMessageRoundTripPreservesEveryField() {
        val message = preKeyMessage(
            signedPreKeyId = 123456,
            oneTimePreKeyId = 654321,
            identityKey = ByteArray(64) { it.toByte() },
            ephemeralKey = ByteArray(64) { (255 - it).toByte() },
            ratchet = ByteArray(200) { (it * 7).toByte() },
        )
        val encoded = CiphertextMessageCodec.encode(message)
        assertContentEquals(encoded, CiphertextMessageCodec.encode(message))
        assertPreKeyMessageEquals(message, CiphertextMessageCodec.decode(encoded))
    }

    @Test
    fun prekeyIdBoundariesRoundTrip() {
        for (id in listOf(0, 1, Int.MAX_VALUE)) {
            val message = preKeyMessage(signedPreKeyId = id, oneTimePreKeyId = id)
            assertPreKeyMessageEquals(message, CiphertextMessageCodec.decode(CiphertextMessageCodec.encode(message)))
        }
        val max = CiphertextMessageCodec.encode(preKeyMessage(signedPreKeyId = Int.MAX_VALUE, oneTimePreKeyId = null))
        assertContentEquals(hex("7fffffff"), max.copyOfRange(2, 6))
    }

    @Test
    fun prekeyIdsWithHighBitSetAreRejected() {
        for (id in listOf("80000000", "ffffffff")) {
            val signed = preKeyVectorWithOneTimePreKey.copyOf().also { hex(id).copyInto(it, 2) }
            assertRejected<ProtocolException.MalformedMessage>(signed)
            val oneTime = preKeyVectorWithOneTimePreKey.copyOf().also { hex(id).copyInto(it, 7) }
            assertRejected<ProtocolException.MalformedMessage>(oneTime)
        }
    }

    @Test
    fun negativePrekeyIdsCannotBeConstructed() {
        assertFailsWith<IllegalArgumentException> { SignedPreKeyId(-1) }
        assertFailsWith<IllegalArgumentException> { OneTimePreKeyId(-1) }
        assertFailsWith<IllegalArgumentException> { SignedPreKeyId(Int.MIN_VALUE) }
    }

    @Test
    fun truncatedPreKeyMessageIsRejected() {
        for (vector in listOf(preKeyVectorWithOneTimePreKey, preKeyVectorWithoutOneTimePreKey)) {
            for (size in 0 until vector.size) {
                assertFailsWith<ProtocolException> { CiphertextMessageCodec.decode(vector.copyOf(size)) }
            }
        }
    }

    @Test
    fun invalidOneTimePreKeyFlagIsRejected() {
        for (flag in listOf(0x02, 0xff)) {
            val bytes = preKeyVectorWithOneTimePreKey.copyOf().also { it[6] = flag.toByte() }
            assertRejected<ProtocolException.MalformedMessage>(bytes)
        }
    }

    @Test
    fun wrongKeySizeIsRejectedOnEncode() {
        for (size in listOf(0, 32, 63, 65)) {
            assertFailsWith<ProtocolException.MalformedMessage> {
                CiphertextMessageCodec.encode(preKeyMessage(identityKey = ByteArray(size)))
            }
            assertFailsWith<ProtocolException.MalformedMessage> {
                CiphertextMessageCodec.encode(preKeyMessage(ephemeralKey = ByteArray(size)))
            }
        }
    }

    @Test
    fun oversizedPreKeyPayloadIsRejected() {
        val tooLarge = preKeyMessage(ratchet = ByteArray(CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE + 1))
        assertFailsWith<ProtocolException.MessageTooLarge> { CiphertextMessageCodec.encode(tooLarge) }
        val lengthOffset = preKeyVectorWithOneTimePreKey.size - 6
        val bytes = preKeyVectorWithOneTimePreKey.copyOf().also { hex("00040001").copyInto(it, lengthOffset) }
        assertRejected<ProtocolException.MessageTooLarge>(bytes)
    }

    @Test
    fun emptyPreKeyPayloadIsRejected() {
        assertFailsWith<ProtocolException.MalformedMessage> {
            CiphertextMessageCodec.encode(preKeyMessage(ratchet = ByteArray(0)))
        }
    }

    @Test
    fun preKeyMessageWithTrailingBytesIsRejected() {
        assertRejected<ProtocolException.MalformedMessage>(preKeyVectorWithOneTimePreKey + byteArrayOf(0))
        assertRejected<ProtocolException.MalformedMessage>(preKeyVectorWithoutOneTimePreKey + hex("00000000"))
    }

    // General

    @Test
    fun emptyInputIsRejected() {
        assertRejected<ProtocolException.MalformedMessage>(ByteArray(0))
        assertRejected<ProtocolException.MalformedMessage>(hex("01"))
    }

    @Test
    fun unsupportedVersionIsRejected() {
        for (version in listOf(0x00, 0x02, 0xff)) {
            val exception = assertFailsWith<ProtocolException.UnsupportedWireVersion> {
                CiphertextMessageCodec.decode(ratchetVector.copyOf().also { it[0] = version.toByte() })
            }
            assertEquals(version, exception.version)
        }
    }

    @Test
    fun unknownMessageTypeIsRejected() {
        for (type in listOf(0x00, 0x03, 0xff)) {
            val exception = assertFailsWith<ProtocolException.UnknownMessageType> {
                CiphertextMessageCodec.decode(ratchetVector.copyOf().also { it[1] = type.toByte() })
            }
            assertEquals(type, exception.type)
        }
    }

    @Test
    fun wireConstantsAreStable() {
        assertEquals(1, CiphertextMessageCodec.WIRE_VERSION)
        assertEquals(1, CiphertextMessageCodec.TYPE_RATCHET_MESSAGE)
        assertEquals(2, CiphertextMessageCodec.TYPE_PREKEY_MESSAGE)
        assertEquals(262_144, CiphertextMessageCodec.MAX_RATCHET_PAYLOAD_SIZE)
        assertEquals(262_144 + 143, CiphertextMessageCodec.MAX_ENCODED_SIZE)
    }

    @Test
    fun protocolInfoStringsAreStable() {
        assertEquals("KSecureMessage-X3DH-v1", ProtocolConstants.X3DH_INFO)
        assertEquals("KSecureMessage-Ratchet-v1", ProtocolConstants.RATCHET_INFO)
    }

    // Real engine output

    @Test
    fun engineMessagesSurviveTheWireFormat() = runTest {
        val engine: ProtocolEngine = KodiumProtocolEngine()
        val alice = engine.party(ALICE)
        val bob = engine.party(BOB)
        fun wire(message: CiphertextMessage) = CiphertextMessageCodec.decode(CiphertextMessageCodec.encode(message))

        val aliceSession = engine.initiateSession(alice.identity, bob.bundle())
        val first = engine.encrypt(aliceSession, "Hello Bob".encodeToByteArray())
        val preKeyMessage = assertIs<PreKeyMessage>(wire(first.message))
        val accepted = engine.accept(bob, ALICE, preKeyMessage)
        assertEquals("Hello Bob", accepted.plaintext.decodeToString())

        val reply = engine.encrypt(accepted.session, "Hello Alice".encodeToByteArray())
        val decrypted = engine.decrypt(first.updatedSession, assertIs<RatchetMessage>(wire(reply.message)))
        assertEquals("Hello Alice", decrypted.plaintext.decodeToString())
    }
}
