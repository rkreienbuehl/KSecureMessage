package dev.kreienbuehl.ksecuremessage.server.ktor

import dev.kreienbuehl.ksecuremessage.model.DeviceAddress
import dev.kreienbuehl.ksecuremessage.model.UserId

/**
 * Log representation of a value that came from a request (S1, finding F5/F6,
 * docs/security-review-remediation.md). Identifiers may contain any UTF-8,
 * including line breaks, so a raw value could end a log line and forge the
 * next one. This escapes, only for the log, every character a line-oriented
 * log could treat as a break or control: `\` → `\\`, `"` → `\"`, CR → `\r`,
 * LF → `\n`, TAB → `\t`, and every other C0/C1 control, DEL, U+2028 and
 * U+2029 → `\uXXXX`. The result is quoted, so an empty value stays visible.
 * The identifier itself is never changed.
 */
internal fun logSafe(value: String): String = buildString(value.length + 2) {
    append('"')
    for (c in value) {
        when {
            c == '\\' -> append("\\\\")
            c == '"' -> append("\\\"")
            c == '\r' -> append("\\r")
            c == '\n' -> append("\\n")
            c == '\t' -> append("\\t")
            c < ' ' || c in '\u007F'..'\u009F' || c == ' ' || c == ' ' -> {
                append("\\u")
                append(c.code.toString(16).uppercase().padStart(4, '0'))
            }
            else -> append(c)
        }
    }
    append('"')
}

/** `user="…" device="…"`, both escaped with [logSafe]. */
internal fun DeviceAddress.forLog(): String = "user=${logSafe(userId.value)} device=${logSafe(deviceId.value)}"

/** `user="…"`, escaped with [logSafe]. */
internal fun UserId.forLog(): String = "user=${logSafe(value)}"
