-- KSecureMessage pre-S1 cleanup, server schema version 8
-- (docs/operating-the-server.md, "Pre-S1 cleanup"; S1.2 finding N5, S1.3 finding N6).
--
-- The only supported way to run it, with the server stopped and after a backup,
-- on an edited copy of this file:
--
--     sqlite3 -bail /path/to/server.db < ksecuremessage-pre-s1-cleanup.sql
--
-- Never paste these statements into an interactive sqlite3 prompt: interactively
-- the shell continues after a failed statement, and the COMMIT below would then
-- commit a partial cleanup. Run as a script, the first error stops the shell with a
-- non-zero exit status and the open transaction is rolled back: nothing changes.
--
-- Edit only the section between ksm-cleanup-input:begin and ksm-cleanup-input:end.
-- The unedited file lists nothing and is refused.

.bail on
.headers off
.mode list
BEGIN IMMEDIATE;

CREATE TEMP TABLE ksm_cleanup_device (user_id TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (user_id, device_id));
CREATE TEMP TABLE ksm_exhausted_user (user_id TEXT NOT NULL PRIMARY KEY);

-- ksm-cleanup-input:begin
-- One row per suspicious registration (from the audit), for example:
--   INSERT INTO ksm_cleanup_device (user_id, device_id) VALUES ('alice', 'evil');
-- Only for an affected user whose ACTIVE recovery key epoch is already
-- 9223372036854775807 and after deciding to revoke it without an epoch change
-- (that user can never register a recovery key again), for example:
--   INSERT INTO ksm_exhausted_user (user_id) VALUES ('alice');
-- ksm-cleanup-input:end

-- 0. Guards: all run before the first change. A failed CHECK names the guard and aborts.
CREATE TEMP TABLE ksm_cleanup_guard (
    server_schema_is_version_8 INTEGER NOT NULL,
    at_least_one_device_listed INTEGER NOT NULL,
    every_listed_device_is_registered INTEGER NOT NULL,
    every_exhausted_user_is_listed_active_and_exhausted INTEGER NOT NULL,
    no_unlisted_exhausted_epoch INTEGER NOT NULL,
    CONSTRAINT server_schema_is_version_8 CHECK (server_schema_is_version_8 = 1),
    CONSTRAINT at_least_one_device_listed CHECK (at_least_one_device_listed = 1),
    CONSTRAINT every_listed_device_is_registered CHECK (every_listed_device_is_registered = 1),
    CONSTRAINT every_exhausted_user_is_listed_active_and_exhausted CHECK (every_exhausted_user_is_listed_active_and_exhausted = 1),
    CONSTRAINT no_unlisted_exhausted_epoch CHECK (no_unlisted_exhausted_epoch = 1)
);
INSERT INTO ksm_cleanup_guard
SELECT
    coalesce((SELECT format FROM main.server_storage WHERE id = 0), 0) = 8,
    EXISTS (SELECT 1 FROM ksm_cleanup_device),
    NOT EXISTS (
        SELECT 1 FROM ksm_cleanup_device c
        WHERE NOT EXISTS (SELECT 1 FROM main.device_registration r WHERE r.user_id = c.user_id AND r.device_id = c.device_id)
    ),
    NOT EXISTS (
        SELECT 1 FROM ksm_exhausted_user x
        WHERE x.user_id NOT IN (SELECT user_id FROM ksm_cleanup_device)
           OR NOT EXISTS (
               SELECT 1 FROM main.last_device_recovery_key_state s
               WHERE s.user_id = x.user_id AND s.state = 1 AND s.epoch = 9223372036854775807
           )
    ),
    NOT EXISTS (
        SELECT 1 FROM main.last_device_recovery_key_state s
        WHERE s.user_id IN (SELECT user_id FROM ksm_cleanup_device)
          AND s.state = 1 AND s.epoch = 9223372036854775807
          AND s.user_id NOT IN (SELECT user_id FROM ksm_exhausted_user)
    );

-- 1. Device-scoped authority and reachability of every listed registration.
DELETE FROM main.device_registration WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device);
DELETE FROM main.authentication_nonce WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device);
-- The prekey bundle fetch is public: a remaining bundle would still start sessions with the attacker.
DELETE FROM main.device_prekey_state WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device);
DELETE FROM main.available_one_time_prekey WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device);
-- consumed_one_time_prekey is kept: a consumed ID must never be handed out again, also
-- after a legitimate device at a known address publishes its prekeys again.
-- Envelopes queued for the invalidated device instance are deleted. Envelopes sent as a
-- listed address are kept: opaque ciphertext that confers no authority.
DELETE FROM main.mailbox_message WHERE (recipient_user_id, recipient_device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device);

-- 2. Recovery authority of every affected user: an ACTIVE key is forced to REVOKED at
--    epoch + 1. Already REVOKED users are left unchanged; users without a row stay
--    unconfigured. The CASE never lets the epoch wrap (the guard already refused it).
UPDATE main.last_device_recovery_key_state
SET state = 2,
    epoch = CASE WHEN epoch < 9223372036854775807 THEN epoch + 1 ELSE NULL END,
    public_key = NULL,
    installed_at = NULL,
    transitioned_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000,
    rotation_id = NULL,
    revocation_id = NULL,
    reset_completion_id = NULL
WHERE state = 1
  AND user_id IN (SELECT user_id FROM ksm_cleanup_device)
  AND user_id NOT IN (SELECT user_id FROM ksm_exhausted_user);
--    Only the users listed in ksm_exhausted_user: REVOKED without an epoch change.
UPDATE main.last_device_recovery_key_state
SET state = 2,
    public_key = NULL,
    installed_at = NULL,
    transitioned_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000,
    rotation_id = NULL,
    revocation_id = NULL,
    reset_completion_id = NULL
WHERE state = 1
  AND user_id IN (SELECT user_id FROM ksm_exhausted_user);
DELETE FROM main.last_device_recovery_key_reset WHERE user_id IN (SELECT user_id FROM ksm_cleanup_device);
DELETE FROM main.last_device_recovery_challenge WHERE user_id IN (SELECT user_id FROM ksm_cleanup_device);

COMMIT;

-- 3. Post-cleanup verification (read-only). Every line must show 0 violations; any
--    violation also fails the script with a non-zero exit status.
CREATE TEMP TABLE ksm_cleanup_check AS
SELECT 'listed_registrations_remaining' AS name, (SELECT count(*) FROM main.device_registration WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device)) AS violations
UNION ALL SELECT 'listed_nonces_remaining', (SELECT count(*) FROM main.authentication_nonce WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device))
UNION ALL SELECT 'listed_prekey_state_remaining', (SELECT count(*) FROM main.device_prekey_state WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device))
UNION ALL SELECT 'listed_available_one_time_prekeys_remaining', (SELECT count(*) FROM main.available_one_time_prekey WHERE (user_id, device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device))
UNION ALL SELECT 'listed_mailbox_rows_remaining', (SELECT count(*) FROM main.mailbox_message WHERE (recipient_user_id, recipient_device_id) IN (SELECT user_id, device_id FROM ksm_cleanup_device))
UNION ALL SELECT 'affected_users_with_active_recovery_key', (SELECT count(*) FROM main.last_device_recovery_key_state WHERE state <> 2 AND user_id IN (SELECT user_id FROM ksm_cleanup_device))
UNION ALL SELECT 'affected_users_pending_resets', (SELECT count(*) FROM main.last_device_recovery_key_reset WHERE user_id IN (SELECT user_id FROM ksm_cleanup_device))
UNION ALL SELECT 'affected_users_challenges', (SELECT count(*) FROM main.last_device_recovery_challenge WHERE user_id IN (SELECT user_id FROM ksm_cleanup_device));
SELECT name, violations FROM ksm_cleanup_check;
CREATE TEMP TABLE ksm_cleanup_verification (
    violations INTEGER NOT NULL,
    CONSTRAINT post_cleanup_verification_found_no_violations CHECK (violations = 0)
);
INSERT INTO ksm_cleanup_verification SELECT coalesce(sum(violations), 1) FROM ksm_cleanup_check;
SELECT 'ksm-pre-s1-cleanup: verification passed';
