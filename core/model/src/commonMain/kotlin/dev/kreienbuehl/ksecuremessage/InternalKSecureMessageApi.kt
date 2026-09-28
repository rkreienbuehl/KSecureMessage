package dev.kreienbuehl.ksecuremessage

/**
 * Marks declarations that are public only because other KSecureMessage
 * modules need them: codecs of frozen formats, sealed record helpers and the
 * storage key rotation machinery. Applications do not need them. They are not
 * covered by the source compatibility promise of the public API and can change
 * in any 0.x release, although the formats they implement stay frozen
 * (docs/releasing.md).
 */
@RequiresOptIn(
    message = "KSecureMessage internal API: used between KSecureMessage modules, not meant for applications.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY, AnnotationTarget.TYPEALIAS)
annotation class InternalKSecureMessageApi
