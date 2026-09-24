package dev.kreienbuehl.ksecuremessage.storage.inmemory

import dev.kreienbuehl.ksecuremessage.storage.ClientStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.ClientStorageContractTest

class InMemoryClientStorageTest : ClientStorageContractTest() {
    override suspend fun newStorage(): ClientStorage = InMemoryClientStorage()
}
