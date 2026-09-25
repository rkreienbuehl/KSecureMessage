package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.AuthenticationNonceRepositoryContractTest

class InMemoryAuthenticationNonceRepositoryTest : AuthenticationNonceRepositoryContractTest() {
    override suspend fun newRepository(): AuthenticationNonceRepository = InMemoryServerStorage().authenticationNonces
}
