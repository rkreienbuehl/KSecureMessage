package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.server.SecureMessageServer
import dev.kreienbuehl.ksecuremessage.storage.inmemory.InMemoryServerStorage
import io.ktor.client.HttpClient
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation

/** Runs [block] against the v1 routes backed by fresh in-memory storage. */
internal fun testServer(block: suspend ApplicationTestBuilder.(storage: InMemoryServerStorage, http: HttpClient) -> Unit) {
    val storage = InMemoryServerStorage()
    testApplication {
        install(ServerContentNegotiation) { json() }
        routing { kSecureMessageRoutes(SecureMessageServer(storage)) }
        val http = createClient { install(ClientContentNegotiation) { json() } }
        block(storage, http)
    }
}
