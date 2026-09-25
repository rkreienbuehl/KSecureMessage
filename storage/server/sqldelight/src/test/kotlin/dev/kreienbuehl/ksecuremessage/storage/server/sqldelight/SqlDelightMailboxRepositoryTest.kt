package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import app.cash.sqldelight.db.SqlDriver
import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.MailboxRepositoryContractTest
import kotlin.test.AfterTest

/** The shared contract on SQLite (one in-memory database per repository). */
class SqlDelightMailboxRepositoryTest : MailboxRepositoryContractTest() {
    private val drivers = mutableListOf<SqlDriver>()

    override suspend fun newRepository(): MailboxRepository =
        SqlDelightServerStorage.open(inMemoryDriver().also { drivers += it }).mailboxes

    @AfterTest
    fun closeDrivers() = drivers.forEach { it.close() }
}
