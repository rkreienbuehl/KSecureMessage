package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import dev.kreienbuehl.ksecuremessage.model.MessageId
import dev.kreienbuehl.ksecuremessage.model.PreKeyMessage
import dev.kreienbuehl.ksecuremessage.model.SessionInitiationVersion
import dev.kreienbuehl.ksecuremessage.protocol.CiphertextMessageCodec
import dev.kreienbuehl.ksecuremessage.protocol.ProtocolEngine
import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A version 1 repetition of the unanswered version 1 initiation that
 * [storage] holds for [recipient], made with the engine directly and stored
 * like the client would have: it stands for one the device sent before its
 * S1.1 upgrade. Since S1.1 the client itself never sends one (finding N3).
 */
internal suspend fun legacyV1Repetition(
    engine: ProtocolEngine,
    storage: ClientStorage,
    sender: DeviceAddress,
    recipient: DeviceAddress,
    plaintext: ByteArray,
): EncryptedEnvelope = storage.transaction {
    val session = assertNotNull(sessions.load(recipient), "a stored session")
    val info = engine.sessionInfo(session)
    assertEquals(SessionInitiationVersion.V1, info.initiationVersion, "a version 1 session")
    assertTrue(info.awaitingReply, "an unanswered initiation")
    val result = engine.encrypt(session, plaintext)
    assertEquals(SessionInitiationVersion.V1, assertIs<PreKeyMessage>(result.message).initiationVersion)
    sessions.store(result.updatedSession)
    EncryptedEnvelope(MessageId("legacy-" + Random.nextLong().toULong()), sender, recipient, payload = CiphertextMessageCodec.encode(result.message))
}
