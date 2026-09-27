package dev.kreienbuehl.ksecuremessage.client

import dev.kreienbuehl.ksecuremessage.model.RecoveryKeyResetStatus
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Whether a recovery key reset is pending for this user, as classified by
 * [SecureMessageClient.recoveryKeyResetAwareness] (docs/recovery-key-reset.md,
 * "Reset awareness"). A read-only composition of the signed recovery key
 * status and the signed reset status: factual states only, no severity and
 * no recommendation. The application decides what to show and what to do.
 *
 * Not an atomic server snapshot: the state can change right after it was
 * read. Every write (cancellation, completion, rotation) is still checked by
 * the server.
 */
sealed interface RecoveryKeyResetAwareness {
    /** No reset is pending. Says nothing about whether a recovery key is configured. */
    data object None : RecoveryKeyResetAwareness

    /**
     * [reset] is pending and, by the client clock at [evaluatedAt], not yet
     * eligible for completion ([evaluatedAt] < [RecoveryKeyResetStatus.Pending.eligibleAt]).
     * A client clock behind the reset's request time also gives this state.
     */
    class Pending(val reset: RecoveryKeyResetStatus.Pending, val evaluatedAt: Instant) : RecoveryKeyResetAwareness {
        /** Time until [RecoveryKeyResetStatus.Pending.eligibleAt] by the client clock; never negative. */
        val remainingUntilEligible: Duration get() = (reset.eligibleAt - evaluatedAt).coerceAtLeast(Duration.ZERO)

        override fun equals(other: Any?): Boolean = other is Pending && reset == other.reset && evaluatedAt == other.evaluatedAt

        override fun hashCode(): Int = 31 * reset.hashCode() + evaluatedAt.hashCode()

        override fun toString(): String = "Pending(reset=$reset, evaluatedAt=$evaluatedAt)"
    }

    /**
     * [reset] is pending and, by the client clock at [evaluatedAt], old
     * enough to be completed ([evaluatedAt] >= [RecoveryKeyResetStatus.Pending.eligibleAt]).
     * Only that: the server decides eligibility with its own clock, so a
     * completion can still be refused (`NOT_YET_ELIGIBLE`), and nobody has
     * approved anything.
     */
    class Eligible(val reset: RecoveryKeyResetStatus.Pending, val evaluatedAt: Instant) : RecoveryKeyResetAwareness {
        override fun equals(other: Any?): Boolean = other is Eligible && reset == other.reset && evaluatedAt == other.evaluatedAt

        override fun hashCode(): Int = 31 * reset.hashCode() + evaluatedAt.hashCode()

        override fun toString(): String = "Eligible(reset=$reset, evaluatedAt=$evaluatedAt)"
    }

    /**
     * The two server views contradicted each other, also after one fresh
     * reread. Impossible while the server keeps its invariants; never read
     * it as [None].
     */
    data class Inconsistent(val reason: RecoveryKeyResetAwarenessInconsistency) : RecoveryKeyResetAwareness
}

/** Why [RecoveryKeyResetAwareness.Inconsistent] was returned. Carries no key material. */
enum class RecoveryKeyResetAwarenessInconsistency {
    /** A reset is pending, but no recovery key is active (unconfigured or revoked). */
    RESET_WITHOUT_ACTIVE_RECOVERY_KEY,

    /** The reset is bound to another recovery key epoch than the active one. */
    RESET_EPOCH_MISMATCH,

    /** The reset is bound to the active epoch but to another recovery public key. */
    RESET_KEY_MISMATCH,

    /** The reset belongs to another user (never retried: no transition explains it). */
    RESET_OF_OTHER_USER,
}
