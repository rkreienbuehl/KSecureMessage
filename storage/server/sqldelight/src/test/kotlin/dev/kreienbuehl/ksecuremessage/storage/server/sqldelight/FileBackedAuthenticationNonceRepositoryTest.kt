package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.AuthenticationNonceRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared contract, including its concurrency tests, on file-backed
 * SQLite: the JDBC driver opens one connection per thread there, so the races
 * run through real SQLite transactions on several connections.
 */
class FileBackedAuthenticationNonceRepositoryTest : AuthenticationNonceRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()

    override suspend fun newRepository(): AuthenticationNonceRepository =
        SqlDelightServerStorage.open(TempDatabase().also { databases += it }.driver()).authenticationNonces

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
