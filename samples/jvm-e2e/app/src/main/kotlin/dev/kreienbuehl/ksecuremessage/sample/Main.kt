package dev.kreienbuehl.ksecuremessage.sample

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import dev.kreienbuehl.ksecuremessage.client.CommitStatus
import dev.kreienbuehl.ksecuremessage.client.DeviceAuthenticationHealth
import dev.kreienbuehl.ksecuremessage.client.ReceiveResult
import dev.kreienbuehl.ksecuremessage.client.SecureMessageClient
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.server.ktor.kSecureMessageRoutes
import dev.kreienbuehl.ksecuremessage.storage.client.inmemory.InMemoryClientStorage
import dev.kreienbuehl.ksecuremessage.storage.server.sqldelight.SqlDelightServerStorage
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.util.Properties
import kotlin.time.Clock

// The minimal application lifecycle of docs/application-lifecycle.md, end to
// end over HTTP: a reference server on a SQLite file, Alice and Bob as two
// clients, one message sent, delivered, committed and acknowledged.
// Every step checks its result; any failure ends the program with an exception.

fun main() = runBlocking {
    // Server: the host owns the SQLite driver and the schema; the storage never
    // creates, migrates or closes it (docs/operating-the-server.md).
    val databaseFile = Files.createTempDirectory("ksecuremessage-sample").resolve("server.db")
    val driver = JdbcSqliteDriver("jdbc:sqlite:$databaseFile", Properties(), SqlDelightServerStorage.Schema)
    val serverStorage = SqlDelightServerStorage.open(driver)
    // No RecoveryKeyResetPolicy: delayed recovery key resets are disabled on this server.
    val server = SecureMessageServer(serverStorage, Clock.System, recoveryKeyResetPolicy = null)
    val http = embeddedServer(CIO, port = 0, host = "127.0.0.1") {
        install(ContentNegotiation) { json() }
        routing { kSecureMessageRoutes(server) }
    }.start(wait = false)
    val port = http.engine.resolvedConnectors().single().port
    val baseUrl = "http://127.0.0.1:$port"
    step("server listening on $baseUrl, database $databaseFile")

    try {
        // Clients: in-memory storage keeps the sample short. A real application
        // uses SqlDelightClientStorage with a platform StorageKeyProvider.
        val aliceAddress = DeviceAddress(UserId("alice"), DeviceId("phone"))
        val bobAddress = DeviceAddress(UserId("bob"), DeviceId("laptop"))
        val alice = SecureMessageClient(aliceAddress, InMemoryClientStorage(), KodiumProtocolEngine(), KtorSecureMessageTransport(baseUrl))
        val bob = SecureMessageClient(bobAddress, InMemoryClientStorage(), KodiumProtocolEngine(), KtorSecureMessageTransport(baseUrl))

        // First launch: local keys, server registration, prekey publication.
        for (client in listOf(alice, bob)) {
            client.initialize()
            client.registerDevice()
            client.publishPreKeys()
        }
        step("alice and bob initialized, registered and published prekeys")

        // Send: the message stays pending on Alice's side until Bob's ACK.
        val sent = alice.send(bobAddress, "Hello Bob".encodeToByteArray())
        check(alice.pendingMessageCount(bobAddress) == 1L) { "the sent message must be pending" }
        step("alice sent ${sent.id}; pending outbound = 1")

        // Receive: drain the mailbox, decrypt, get a Delivery (not yet acknowledged).
        val delivered = bob.receive().map { bob.decrypt(it) }
        val delivery = delivered.single() as? ReceiveResult.Delivery ?: error("expected a Delivery, got $delivered")
        val text = delivery.message.plaintext.decodeToString()
        check(text == "Hello Bob") { "unexpected plaintext" }
        check(bob.pendingReceivedMessageCount() == 1L) { "the delivery must be pending until committed" }
        step("bob received a Delivery from ${delivery.sender}: \"$text\"")

        // The application applies the message durably (here: it prints it),
        // then commits it; the commit sends the ACK.
        val commit = bob.commitReceivedMessage(delivery.message)
        check(commit.status == CommitStatus.COMMITTED && commit.ackSent) { "commit failed: ${commit.status}, ackSent=${commit.ackSent}" }
        check(bob.pendingReceivedMessageCount() == 0L) { "nothing may stay pending after the commit" }
        step("bob committed ${commit.id} and sent the ACK")

        // The ACK reaches Alice and clears her pending outbound message.
        val acks = alice.receive().map { alice.decrypt(it) }
        val ack = acks.single() as? ReceiveResult.Acknowledgement ?: error("expected an Acknowledgement, got $acks")
        check(ack.id == sent.id && ack.cleared) { "the ACK must clear the sent message" }
        check(alice.pendingMessageCount() == 0L) { "alice must have no pending outbound message" }
        step("alice received the ACK; pending outbound = 0")

        // Optional checks: both sides derive the same safety number, and
        // Alice's server credentials are healthy.
        val aliceView = alice.safetyNumber(bobAddress)
        val bobView = bob.safetyNumber(aliceAddress)
        check(aliceView == bobView) { "safety numbers differ" }
        step("safety number ${aliceView.displayString}")
        val health = alice.deviceAuthenticationHealth()
        check(health is DeviceAuthenticationHealth.Healthy) { "unexpected health $health" }
        step("alice device authentication health: Healthy")

        println("E2E PASSED")
    } finally {
        // Shutdown: stop the HTTP server, then close the driver the host owns.
        http.stop(gracePeriodMillis = 0, timeoutMillis = 1_000)
        driver.close()
    }
}

private fun step(message: String) = println("[sample] $message")
