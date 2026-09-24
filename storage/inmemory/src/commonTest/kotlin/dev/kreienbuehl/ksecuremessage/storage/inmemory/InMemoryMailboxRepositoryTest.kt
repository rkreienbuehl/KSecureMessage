package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.storage.MailboxRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.MailboxRepositoryContractTest

class InMemoryMailboxRepositoryTest : MailboxRepositoryContractTest() {
    override suspend fun newRepository(): MailboxRepository = InMemoryServerStorage().mailboxes
}
