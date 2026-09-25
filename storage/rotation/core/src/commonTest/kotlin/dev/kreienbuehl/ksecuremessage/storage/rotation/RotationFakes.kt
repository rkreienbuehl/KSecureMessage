package dev.kreienbuehl.ksecuremessage.storage.rotation

import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionException
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageEncryptionKey
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyId
import dev.kreienbuehl.ksecuremessage.storage.encryption.StorageKeyProvider

class InjectedCrash(message: String) : IllegalStateException(message)

/**
 * An in-memory [StorageKeyRotationBackend]: the persisted state, the key ID
 * of every sealed record and the key checks. Each call is atomic; transitions
 * are compare-and-set like a real backend. Writes are logged to [log], shared
 * with [RecordingKeyProvider], so tests can check the order of steps.
 */
class FakeRotationBackend(val log: MutableList<String>, records: Int = 5) : StorageKeyRotationBackend {
    var state: StorageKeyRotationState = StorageKeyRotationState.Stable(K1, K1)

    /** The key ID in the header of every sealed record. */
    val records: MutableList<StorageKeyId> = MutableList(records) { K1 }

    /**
     * Sealed values the batches never select but the key reference scan sees,
     * like a key check or a sealed location a batch forgot.
     */
    val otherSealedValues: MutableList<StorageKeyId> = mutableListOf()

    /** Steps (`prepare`, `activate`, `migrate`, `retiring`, `complete`) that throw right after they committed. */
    val crashAfter = mutableSetOf<String>()

    private var exclusiveDepth = 0

    override suspend fun <T> exclusive(block: suspend () -> T): T {
        check(exclusiveDepth == 0) { "nested rotation step" }
        exclusiveDepth++
        try {
            return block()
        } finally {
            exclusiveDepth--
        }
    }

    override suspend fun state(): StorageKeyRotationState = state.also { requireExclusive() }

    override suspend fun remainingRecords(): Long = records.count { it != state.currentKeyId }.toLong()

    override suspend fun prepare(from: StorageKeyRotationState.Stable, nextKeyId: StorageKeyId) = commit("prepare", from) {
        log += "prepare ${nextKeyId.value}"
        StorageKeyRotationState.Preparing(from.currentKeyId, nextKeyId, nextKeyId)
    }

    override suspend fun activate(from: StorageKeyRotationState.Preparing, key: StorageEncryptionKey) = commit("activate", from) {
        check(key.id == from.nextKeyId) { "activated another key" }
        log += "activate ${key.id.value}"
        StorageKeyRotationState.Migrating(key.id, from.highestKeyId, from.currentKeyId)
    }

    override suspend fun migrateBatch(from: StorageKeyRotationState.Migrating, maxRecords: Int): Long {
        commit("migrate", from) {
            var budget = maxRecords
            for (i in records.indices) {
                if (budget == 0) break
                if (records[i] != from.currentKeyId) {
                    // Like a record that names a key the storage does not have: the batch fails.
                    if (records[i] != from.retiringKeyId) throw StorageEncryptionException.KeyUnavailable("unknown key")
                    records[i] = from.currentKeyId
                    budget--
                }
            }
            log += "migrate ${maxRecords - budget}"
            from
        }
        return remainingRecords()
    }

    override suspend fun keyReferences(): Map<StorageKeyId, Long> {
        requireExclusive()
        return references(state)
    }

    override suspend fun markRetiring(
        from: StorageKeyRotationState.Migrating,
        requireRetirable: (Map<StorageKeyId, Long>) -> Unit,
    ) = commit("retiring", from) {
        val next = StorageKeyRotationState.Retiring(from.currentKeyId, from.highestKeyId, from.retiringKeyId)
        // The proof runs inside the transaction; throwing rolls it back.
        requireRetirable(references(next))
        log += "retiring ${from.retiringKeyId.value}"
        next
    }

    override suspend fun complete(from: StorageKeyRotationState.Retiring) = commit("complete", from) {
        log += "complete"
        StorageKeyRotationState.Stable(from.currentKeyId, from.highestKeyId)
    }

    /** Records plus key checks: the current check, and the retiring one only while MIGRATING. */
    private fun references(state: StorageKeyRotationState): Map<StorageKeyId, Long> {
        val all = records + otherSealedValues + state.currentKeyId + listOfNotNull((state as? StorageKeyRotationState.Migrating)?.retiringKeyId)
        return all.groupingBy { it }.eachCount().mapValues { it.value.toLong() }
    }

    private fun requireExclusive() = check(exclusiveDepth == 1) { "rotation step outside exclusive" }

    private suspend fun commit(step: String, from: StorageKeyRotationState, change: () -> StorageKeyRotationState) {
        requireExclusive()
        if (state != from) throw IllegalStateException("Storage encryption state changed while rotating")
        val savedRecords = records.toList()
        val savedLog = log.size
        try {
            state = change()
        } catch (e: Throwable) {
            records.clear()
            records += savedRecords
            while (log.size > savedLog) log.removeAt(log.lastIndex)
            throw e
        }
        if (step in crashAfter) throw InjectedCrash("crash after $step")
    }
}

/** A [StorageKeyProvider] that logs every call to [log], with failure hooks. */
class RecordingKeyProvider(private val log: MutableList<String>) : StorageKeyProvider {
    val keys = mutableMapOf(K1 to StorageEncryptionKey.generate(K1))
    var failCreate = false
    var crashAfterCreate = false
    var crashAfterRemove = false

    /** [key] returns different bytes than [createKey] stored. */
    var returnOtherKey = false

    /** [key] returns `null`. */
    var loseOnRead = false

    override suspend fun loadOrCreateKey(): StorageEncryptionKey = error("not used by rotation")

    override suspend fun key(id: StorageKeyId): StorageEncryptionKey? {
        log += "key ${id.value}"
        if (loseOnRead) return null
        if (returnOtherKey) return StorageEncryptionKey.generate(id)
        return keys[id]
    }

    override suspend fun createKey(id: StorageKeyId): StorageEncryptionKey {
        if (failCreate) throw StorageEncryptionException.KeyUnavailable("injected")
        log += "createKey ${id.value}"
        val key = keys.getOrPut(id) { StorageEncryptionKey.generate(id) }
        if (crashAfterCreate) throw InjectedCrash("crash after createKey")
        return key
    }

    override suspend fun removeKey(id: StorageKeyId): Boolean {
        val removed = id in keys
        log += "removeKey ${id.value} $removed"
        if (!removed) return false
        check(keys.size > 1) { "last key" }
        keys.remove(id)
        if (crashAfterRemove) throw InjectedCrash("crash after removeKey")
        return true
    }
}

val K1 = StorageKeyId(1)
val K2 = StorageKeyId(2)
val K3 = StorageKeyId(3)
