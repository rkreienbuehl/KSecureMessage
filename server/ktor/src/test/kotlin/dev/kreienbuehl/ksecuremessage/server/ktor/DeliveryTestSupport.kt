package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.CommitResult
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.ReceivedMessage
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.model.EncryptedEnvelope
import kotlin.test.assertIs

/** A delivered message and the result of committing it. */
internal class Accepted(val message: ReceivedMessage, val commit: CommitResult) {
    val id get() = message.id
    val plaintext get() = message.plaintext
    val ackSent get() = commit.ackSent
}

/**
 * Decrypts [envelope], expects an application message and commits it, as an
 * application does after applying it (docs/application-delivery.md). The
 * commit sends the acknowledgement.
 */
internal suspend fun SecureMessageClient.accept(envelope: EncryptedEnvelope): Accepted {
    val message = assertIs<ReceiveResult.Delivery>(decrypt(envelope)).message
    return Accepted(message, commitReceivedMessage(message))
}
