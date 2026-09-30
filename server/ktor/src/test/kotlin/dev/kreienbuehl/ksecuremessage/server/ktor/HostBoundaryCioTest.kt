package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceId
import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.server.DeviceRegistrationAuthorizer
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.application.serverConfig
import io.ktor.server.cio.CIO
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.coroutines.cancellation.CancellationException
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * N7 (S1.3) on a real CIO engine, not only Ktor's test host: host code at the
 * registration boundaries throws a synthetic [CancellationException] (while
 * the call is still active), one with a secret cause, or an [InternalError].
 * The reviewer reproduced the leak on CIO, where an escaping throwable's
 * message could become the 500 body. Expected: exactly
 * `{"error":"internal_error"}`, nothing secret in the body or the log, in
 * production and development mode.
 */
class HostBoundaryCioTest {
    private val alice = DeviceAddress(UserId("alice"), DeviceId("phone"))

    private fun failures(): List<Throwable> = listOf(
        CancellationException("SECRET-CANCEL principal=alice"),
        CancellationException("cancelled").apply { initCause(IllegalStateException("SECRET-CAUSE principal=alice")) },
        InternalError("SECRET-VM principal=alice"),
    )

    private class Outcome(val status: Int, val body: String, val logged: String, val registered: Boolean)

    private fun runOnCio(
        authorizer: DeviceRegistrationAuthorizer<TestRegistrationPrincipal>,
        extractor: DeviceRegistrationContextExtractor<TestRegistrationPrincipal>,
        developmentMode: Boolean,
    ): Outcome {
        val logger = RecordingLogger()
        val storage = InMemoryServerStorage()
        val engine = embeddedServer(
            CIO,
            rootConfig = serverConfig(applicationEnvironment { log = logger }) {
                this.developmentMode = developmentMode
                module {
                    install(ContentNegotiation) { json() }
                    routing { kSecureMessageRoutes(SecureMessageServer(storage, Clock.System, authorizer), extractor) }
                }
            },
            configure = { connector { host = "127.0.0.1"; port = 0 } },
        )
        engine.start(wait = false)
        try {
            val port = runBlocking { engine.engine.resolvedConnectors().first().port }
            val device = TestDevice(alice)
            val body = """{"publicKey":"${Base64.encode(device.keyPair.publicKey)}"}""".encodeToByteArray()
            val authentication = device.sign("PUT", ServerApiPaths.REGISTRATION, body)
            val request = HttpRequest.newBuilder(URI("http://127.0.0.1:$port${ServerApiPaths.device(alice, ServerApiPaths.REGISTRATION)}"))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(body))
                .header("Content-Type", "application/json")
                .header(AuthHeaders.VERSION, AuthHeaders.CURRENT_VERSION)
                .header(AuthHeaders.TIMESTAMP, authentication.timestamp.toEpochMilliseconds().toString())
                .header(AuthHeaders.NONCE, Base64.encode(authentication.nonce.bytes))
                .header(AuthHeaders.SIGNATURE, Base64.encode(authentication.signature))
                .header(TestRegistrationContexts.PRINCIPAL_HEADER, "alice")
                .build()
            val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
            return Outcome(response.statusCode(), response.body(), logger.everything(), runBlocking { storage.devices.registration(alice) } != null)
        } finally {
            engine.stop(0, 1_000)
        }
    }

    private fun assertSanitized(outcome: Outcome, what: String) {
        assertEquals(500, outcome.status, what)
        assertEquals("""{"error":"internal_error"}""", outcome.body, what)
        assertFalse(outcome.body.contains("SECRET"), "no host text in the body: $what")
        assertFalse(outcome.logged.contains("SECRET"), "no host text, cause or stack in the log: $what")
        assertTrue(outcome.logged.contains("Registration authorization failed"), "reported as a host failure: $what")
        assertFalse(outcome.registered, "nothing registered: $what")
    }

    @Test
    fun n7ExtractorFailuresAreSanitizedOnCio() {
        for (failure in failures()) for (developmentMode in listOf(false, true)) {
            val authorizer = TestDeviceRegistrationAuthorizer.allowAll()
            val outcome = runOnCio(authorizer, DeviceRegistrationContextExtractor { throw failure }, developmentMode)
            assertSanitized(outcome, "extractor ${failure::class.simpleName} developmentMode=$developmentMode")
            assertTrue(authorizer.requests.isEmpty())
        }
    }

    @Test
    fun n7AuthorizerFailuresAreSanitizedOnCio() {
        for (failure in failures()) for (developmentMode in listOf(false, true)) {
            val outcome = runOnCio(TestDeviceRegistrationAuthorizer.throwing(failure), TestRegistrationContexts.header, developmentMode)
            assertSanitized(outcome, "authorizer ${failure::class.simpleName} developmentMode=$developmentMode")
        }
    }
}
