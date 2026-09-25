package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.client.ServerRequestSigner
import dev.kreienbuehl.ksecuremessage.client.ktor.KtorSecureMessageTransport
import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.DeviceRegistration
import dev.kreienbuehl.ksecuremessage.protocol.DeviceAuthenticationKeyPair
import dev.kreienbuehl.ksecuremessage.protocol.KodiumProtocolEngine
import dev.kreienbuehl.ksecuremessage.protocol.RequestAuthentication
import dev.kreienbuehl.ksecuremessage.protocol.RequestNonce
import dev.kreienbuehl.ksecuremessage.protocol.ServerApiPaths
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequest
import dev.kreienbuehl.ksecuremessage.protocol.ServerRequestAuthentication
import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.server.inmemory.InMemoryServerStorage
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.content.ByteArrayContent
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Instant
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation

/** Runs [block] against the v1 routes backed by fresh in-memory storage, with [clock] as the server time. */
internal fun testServer(
    clock: Clock = Clock.System,
    block: suspend ApplicationTestBuilder.(storage: InMemoryServerStorage, http: HttpClient) -> Unit,
) {
    val storage = InMemoryServerStorage()
    testApplication {
        install(ServerContentNegotiation) { json() }
        routing { kSecureMessageRoutes(SecureMessageServer(storage, clock)) }
        val http = createClient { install(ClientContentNegotiation) { json() } }
        block(storage, http)
    }
}

/** A clock the test sets by hand. */
internal class ManualClock(var now: Instant = Instant.fromEpochMilliseconds(1_767_225_600_000)) : Clock {
    override fun now(): Instant = now
}

/** A device with its own authentication key, signing with [clock]. */
internal class TestDevice(val address: DeviceAddress, private val clock: Clock = Clock.System) {
    val keyPair: DeviceAuthenticationKeyPair = runBlocking { KodiumProtocolEngine().createDeviceAuthenticationKey() }

    val signer = ServerRequestSigner { ServerRequestAuthentication.sign(keyPair, it, clock.now()) }

    /** Signs an arbitrary request, for tests that tamper with what is sent. */
    fun sign(
        method: String,
        endpoint: String,
        body: ByteArray,
        address: DeviceAddress = this.address,
        timestamp: Instant = clock.now(),
        nonce: RequestNonce = RequestNonce.random(),
    ): RequestAuthentication =
        ServerRequestAuthentication.sign(keyPair, ServerRequest(address, method, ServerApiPaths.device(address, endpoint), body), timestamp, nonce)

    suspend fun register(transport: KtorSecureMessageTransport) =
        transport.registerDevice(DeviceRegistration(address, keyPair.publicKey), signer)
}

/** Sends a raw request with [authentication] in the v1 headers, or none. [body] `null` sends no body. */
internal suspend fun HttpClient.raw(
    method: HttpMethod,
    path: String,
    body: ByteArray?,
    authentication: RequestAuthentication?,
    extraHeaders: Map<String, String> = emptyMap(),
): HttpResponse = request(path) {
    this.method = method
    if (authentication != null) {
        header(AuthHeaders.VERSION, AuthHeaders.CURRENT_VERSION)
        header(AuthHeaders.TIMESTAMP, authentication.timestamp.toEpochMilliseconds().toString())
        header(AuthHeaders.NONCE, Base64.encode(authentication.nonce.bytes))
        header(AuthHeaders.SIGNATURE, Base64.encode(authentication.signature))
    }
    for ((name, value) in extraHeaders) header(name, value)
    if (body != null) setBody(ByteArrayContent(body, ContentType.Application.Json))
}
