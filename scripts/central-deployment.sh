#!/usr/bin/env bash
# Central Portal deployment status and drop (docs/releasing.md, "Remote
# publication"). Never publishes: there is deliberately no "publish" command;
# a release is published by the maintainer in the Portal.
#
#   central-deployment.sh status <deployment id>   prints deploymentState (VALIDATED, FAILED, ...)
#   central-deployment.sh wait <deployment id>     polls until VALIDATED (exit 0) or FAILED (exit 1)
#   central-deployment.sh drop <deployment id>     deletes an unpublished deployment
#
# Credentials: mavenCentralUsername / mavenCentralPassword from the environment
# (ORG_GRADLE_PROJECT_*) or ~/.gradle/gradle.properties. The token goes to curl
# through a private header file, never on a command line, and is never printed.
set -euo pipefail

command="${1:?status|wait|drop}"
id="${2:?deployment id}"
api="https://central.sonatype.com/api/v1/publisher"

property() {
    local name="$1" variable="ORG_GRADLE_PROJECT_$1"
    if [ -n "${!variable:-}" ]; then printf '%s' "${!variable}"; return; fi
    sed -n "s/^$name=//p" "${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties" | tail -1
}

headers="$(mktemp)"
trap 'rm -f "$headers"' EXIT
chmod 600 "$headers"
user="$(property mavenCentralUsername)"
password="$(property mavenCentralPassword)"
[ -n "$user" ] && [ -n "$password" ] || { echo "no mavenCentralUsername/mavenCentralPassword" >&2; exit 1; }
printf 'Authorization: Bearer %s\n' "$(printf '%s:%s' "$user" "$password" | base64 | tr -d '\n')" > "$headers"
unset user password

state() {
    curl -sf -X POST -H @"$headers" "$api/status?id=$id" |
        python3 -c 'import json, sys; d = json.load(sys.stdin); print(d["deploymentState"]); [print("  error:", e) for e in (d.get("errors") or {}).values()]'
}

case "$command" in
    status) state ;;
    wait)
        for _ in $(seq 1 120); do
            current="$(state)"
            echo "$current" | head -1
            case "$(echo "$current" | head -1)" in
                VALIDATED) exit 0 ;;
                FAILED) echo "$current"; exit 1 ;;
                PUBLISHING|PUBLISHED) echo "deployment is being published: not expected here" >&2; exit 1 ;;
            esac
            sleep 15
        done
        echo "timed out waiting for validation" >&2; exit 1 ;;
    drop)
        code="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H @"$headers" "$api/deployment/$id")"
        echo "drop: HTTP $code"
        [ "$code" = "204" ] ;;
    *) echo "unknown command $command" >&2; exit 2 ;;
esac
