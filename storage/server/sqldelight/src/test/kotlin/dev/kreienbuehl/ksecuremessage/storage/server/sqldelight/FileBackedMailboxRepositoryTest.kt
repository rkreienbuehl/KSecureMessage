package dev.kreienbuehl.ksecuremessage.storage.server.sqldelight

import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.MailboxRepositoryContractTest
import kotlin.test.AfterTest

/**
 * The shared contract, including its concurrency tests, on file-backed
 * SQLite: the JDBC driver opens one connection per thread there, so the races
 * run through real SQLite transactions on several connections.
 */
class FileBackedMailboxRepositoryTest : MailboxRepositoryContractTest() {
    private val databases = mutableListOf<TempDatabase>()

    override suspend fun newRepository(): MailboxRepository =
        SqlDelightServerStorage.open(TempDatabase().also { databases += it }.driver()).mailboxes

    @AfterTest
    fun deleteDatabases() = databases.forEach { it.close() }
}
