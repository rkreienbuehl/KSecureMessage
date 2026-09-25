package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.AuthenticationNonceRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.AuthenticationNonceRepositoryContractTest
import kotlin.test.AfterTest

/** The shared contract on SQLite (one in-memory database per repository). */
class SqlDelightAuthenticationNonceRepositoryTest : AuthenticationNonceRepositoryContractTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override suspend fun newRepository(): AuthenticationNonceRepository =
        SqlDelightServerStorage.open(inMemoryDriver().also { drivers += it }).authenticationNonces

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}
