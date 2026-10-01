# Security policy

KSecureMessage is pre-1.0 and has **not** had a comprehensive security
audit. The threat model, known limitations and the reviewer checklist are in
the
[security review guide](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/security-review.md);
the findings of the targeted security review, the independent re-review
results and the accepted residual risks are in the
[remediation record](https://github.com/rkreienbuehl/KSecureMessage/blob/main/docs/security-review-remediation.md).

## Supported versions

| Version | Receives security fixes |
|---|---|
| latest 0.x release (currently the 0.1 line, starting with `0.1.0`) | yes |
| older 0.x releases, snapshots, internal prereleases | no |

Fixes ship in a new release of the latest 0.x line; there are no backports.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting:

**<https://github.com/rkreienbuehl/KSecureMessage/security/advisories/new>**

Do **not** open a public issue, pull request or discussion for a
vulnerability that is not yet public. There is no separate security e-mail
address.

Please include what you can of:

- the affected module(s) and version or commit;
- the affected component (for example wire format, session setup, storage
  encryption, server authentication, recovery) and platform;
- a description of the issue and its impact: what an attacker can read,
  forge, replay or deny, and what position they need (network, server,
  another device, local storage access);
- steps or a test case to reproduce it;
- whether it is already known to others or public.

## What to expect

This is a project maintained by one person on a best-effort basis. Reports
are acknowledged and handled through the private advisory, but no response
or fix time is guaranteed. Once a fix is released, the advisory is published
and credits the reporter unless they ask not to be named.
