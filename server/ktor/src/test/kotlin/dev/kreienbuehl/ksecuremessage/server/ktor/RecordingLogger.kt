package dev.kreienbuehl.ksecuremessage.server.ktor

import org.slf4j.Marker
import org.slf4j.event.Level
import org.slf4j.helpers.LegacyAbstractLogger
import org.slf4j.helpers.MessageFormatter

/** Records every formatted log event and, separately, the full text of every logged throwable. */
internal class RecordingLogger : LegacyAbstractLogger() {
    val events = mutableListOf<String>()
    val throwables = mutableListOf<String>()

    override fun getName() = "recording"
    override fun isTraceEnabled() = true
    override fun isDebugEnabled() = true
    override fun isInfoEnabled() = true
    override fun isWarnEnabled() = true
    override fun isErrorEnabled() = true
    override fun getFullyQualifiedCallerName(): String? = null

    override fun handleNormalizedLoggingCall(level: Level, marker: Marker?, pattern: String?, arguments: Array<out Any?>?, throwable: Throwable?) {
        synchronized(events) {
            events += MessageFormatter.basicArrayFormat(pattern, arguments)
            if (throwable != null) throwables += throwable.stackTraceToString()
        }
    }

    /** Everything logged, messages and throwables, as one text. */
    fun everything(): String = synchronized(events) { (events + throwables).joinToString("\n") }
}
