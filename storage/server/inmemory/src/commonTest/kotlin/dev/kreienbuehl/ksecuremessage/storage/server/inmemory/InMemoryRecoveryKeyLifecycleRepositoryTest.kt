package dev.kreienbuehl.ksecuremessage.storage.server.inmemory

import dev.kreienbuehl.ksecuremessage.model.UserId
import dev.kreienbuehl.ksecuremessage.storage.ServerStorage
import dev.kreienbuehl.ksecuremessage.storage.testing.RecoveryKeyLifecycleRepositoryContractTest

class InMemoryRecoveryKeyLifecycleRepositoryTest : RecoveryKeyLifecycleRepositoryContractTest() {
    override suspend fun newStorage(): ServerStorage = InMemoryServerStorage()

    override suspend fun setRecoveryKeyEpoch(storage: ServerStorage, userId: UserId, epoch: Long) =
        (storage as InMemoryServerStorage).setRecoveryKeyEpochForTesting(userId, epoch)
}
