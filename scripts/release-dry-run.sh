#!/usr/bin/env bash
# Local release dry run (docs/releasing.md, "Release checklist", steps 4–6, 9
# and 10). Runs each gate in order, stops at the first failure and prints
# PASSED / FAILED / NOT EXECUTED per gate. Hosted CI, Android instrumentation,
# the keychain hosts, the Central Portal deployment and the Pages deployment
# are separate gates of the checklist and are not run here.
#
#   scripts/release-dry-run.sh            local gates only
#   scripts/release-dry-run.sh --remote   also publishToMavenCentral + verifyRemotePublication (SNAPSHOT only)
#
# Signing and Central credentials come from ~/.gradle/gradle.properties or the
# environment (docs/releasing.md); this script never reads or prints them.
set -uo pipefail
cd "$(dirname "$0")/.."

remote=false
[ "${1:-}" = "--remote" ] && remote=true

gates=()
results=()
stopped=false

gate() {
    local name="$1"; shift
    if $stopped; then
        gates+=("$name"); results+=("NOT EXECUTED")
        return
    fi
    echo "=== $name: $*"
    if "$@"; then
        gates+=("$name"); results+=("PASSED")
    else
        gates+=("$name"); results+=("FAILED"); stopped=true
    fi
}

signing_configured() {
    # Names only; values are never read into this script.
    grep -Eqs '^(signingInMemoryKey|signing\.gnupg\.keyName)=' "${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties" ||
        [ -n "${ORG_GRADLE_PROJECT_signingInMemoryKey:-}" ] || [ -n "${ORG_GRADLE_PROJECT_signing_gnupg_keyName:-}" ]
}

gate "clean working tree" bash -c '[ -z "$(git status --porcelain)" ]'
gate "default build" ./gradlew build
gate "test matrix executed" ./gradlew verifyTestExecution
gate "API compatibility" ./gradlew checkKotlinAbi
if signing_configured; then
    gate "publication, consumer fixture, signatures" ./gradlew verifyPublication verifyReleaseSignatures
else
    gate "publication and consumer fixture (UNSIGNED: no signing inputs)" ./gradlew verifyPublication
    gates+=("signatures"); results+=("NOT EXECUTED")
fi
gate "documentation site (mkdocs build --strict)" ./gradlew docsSite
if $remote; then
    gate "upload to Maven Central" ./gradlew publishToMavenCentral
    gate "remote artifacts, signatures, remote consumer" ./gradlew verifyRemotePublication
else
    gates+=("remote publication"); results+=("NOT EXECUTED")
fi

echo
echo "Release dry run:"
failed=0
for i in "${!gates[@]}"; do
    printf '  %-55s %s\n' "${gates[$i]}" "${results[$i]}"
    [ "${results[$i]}" = "FAILED" ] && failed=1
done
exit $failed
