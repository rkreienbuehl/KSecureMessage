package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.storage.PreKeyRepository
import dev.kreienbuehl.ksecuremessage.storage.testing.PreKeyRepositoryContractTest

class InMemoryPreKeyRepositoryTest : PreKeyRepositoryContractTest() {
    override suspend fun newRepository(): PreKeyRepository = InMemoryServerStorage().preKeys
}
