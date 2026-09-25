#!/usr/bin/env bash
# Runs the DataProtection Keychain tests of one Kotlin/Native test binary in a
# signed, entitled host application (docs/storage-key-providers.md,
# "Signed keychain host"). Called by the <target>KeychainHost* Gradle tasks
# with KEY=VALUE arguments:
#
#   PLATFORM   macos | ios-simulator
#   KEXE       the test.kexe built by linkDebugTest<Target>
#   WORK       build directory for the bundle and logs
#   LABEL      module and target, for the result line
#   MODES      space-separated: tests relaunch leftover purge
#   TEAM_ID, SIGNING_IDENTITY, MACOS_PROFILE, BUNDLE_ID   macOS signing
#   SIMULATOR  simulator UDID or "booted"
#   REQUIRED   true: NOT EXECUTED fails the task
#
# Result line: PASSED, FAILED, or NOT EXECUTED (signing/entitlement
# environment unavailable). Never prints key material; the tests do not
# print any either.
set -uo pipefail

for arg in "$@"; do
    case "$arg" in
        *=*) printf -v "ARG_${arg%%=*}" '%s' "${arg#*=}" ;;
        *) echo "unexpected argument: $arg" >&2; exit 2 ;;
    esac
done
PLATFORM="${ARG_PLATFORM:?}"
KEXE="${ARG_KEXE:?}"
WORK="${ARG_WORK:?}"
LABEL="${ARG_LABEL:?}"
MODES="${ARG_MODES:-tests}"
TEAM_ID="${ARG_TEAM_ID:-}"
SIGNING_IDENTITY="${ARG_SIGNING_IDENTITY:-}"
MACOS_PROFILE="${ARG_MACOS_PROFILE:-}"
BUNDLE_ID="${ARG_BUNDLE_ID:-dev.kreienbuehl.ksecuremessage.keychainhost}"
SIMULATOR="${ARG_SIMULATOR:-booted}"
REQUIRED="${ARG_REQUIRED:-false}"

HERE="$(cd "$(dirname "$0")" && pwd)"
# The simulator reads entitlements from the __entitlements section linked into
# the binary (ios-simulator.entitlements); its identifiers are fixed there.
SIMULATOR_BUNDLE_ID="dev.kreienbuehl.ksecuremessage.keychainhost"
SIMULATOR_TEAM="KSMTEST000"
EXECUTABLE="KeychainHost"
TEST_FILTER='*DataProtection*-*DataProtectionRelaunch*:*DataProtectionLeftover*:*DataProtectionPurge*'

result() { echo "KEYCHAIN HOST $LABEL: $*"; }

not_executed() {
    result "NOT EXECUTED — signing/entitlement environment unavailable ($1)"
    [ "$REQUIRED" = "true" ] && exit 1
    exit 0
}

failed() {
    result "FAILED — $1"
    exit 1
}

# SHA-1 of the valid code signing identity whose certificate belongs to $TEAM_ID.
identity_for_team() {
    local hash pem
    for hash in $(security find-identity -v -p codesigning | awk '/"Apple Development/ {print $2}'); do
        pem="$(security find-certificate -a -Z -p | awk -v h="$hash" '
            /^SHA-1 hash:/ { found = ($3 == h) }
            found && /BEGIN CERTIFICATE/ { copy = 1 }
            copy { print }
            copy && /END CERTIFICATE/ { exit }')"
        if [ -n "$pem" ] && echo "$pem" | openssl x509 -noout -subject 2>/dev/null | grep -q "OU *= *$TEAM_ID"; then
            echo "$hash"
            return 0
        fi
    done
    return 1
}

plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

prepare_macos() {
    [ -n "$TEAM_ID" ] || not_executed "ksm.apple.teamId is not set"
    [ -n "$MACOS_PROFILE" ] || not_executed "ksm.apple.macosProfile is not set"
    [ -f "$MACOS_PROFILE" ] || not_executed "provisioning profile $MACOS_PROFILE does not exist"

    local decoded="$WORK/profile.plist"
    security cms -D -i "$MACOS_PROFILE" > "$decoded" 2>/dev/null || not_executed "cannot decode $MACOS_PROFILE"
    local app_id
    app_id="$(plist_value "$decoded" "Entitlements:com.apple.application-identifier")"
    plist_value "$decoded" "Platform" | grep -q OSX || not_executed "profile is not a macOS profile"
    case "$app_id" in
        "$TEAM_ID.$BUNDLE_ID" | "$TEAM_ID.*") ;;
        *) not_executed "profile application identifier $app_id does not match $TEAM_ID.$BUNDLE_ID" ;;
    esac
    local expiry
    expiry="$(plist_value "$decoded" "ExpirationDate")"
    [ "$(date -j -f '%a %b %d %T %Z %Y' "$expiry" +%s 2>/dev/null || echo 0)" -gt "$(date +%s)" ] || not_executed "profile expired ($expiry)"

    local identity="$SIGNING_IDENTITY"
    if [ -z "$identity" ]; then
        identity="$(identity_for_team)" || not_executed "no valid Apple Development identity of team $TEAM_ID"
    fi

    APP="$WORK/$EXECUTABLE.app"
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS"
    cp "$KEXE" "$APP/Contents/MacOS/$EXECUTABLE"
    cp "$MACOS_PROFILE" "$APP/Contents/embedded.provisionprofile"
    info_plist "$APP/Contents/Info.plist" "$BUNDLE_ID" MacOSX
    sed -e "s/@TEAM@/$TEAM_ID/g" -e "s/@BUNDLE@/$BUNDLE_ID/g" "$HERE/macos.entitlements.template" > "$WORK/macos.entitlements"

    codesign --force --sign "$identity" --timestamp=none --entitlements "$WORK/macos.entitlements" "$APP" > "$WORK/codesign.log" 2>&1 ||
        failed "codesign failed: $(tail -1 "$WORK/codesign.log")"
    codesign --verify --strict "$APP" 2>> "$WORK/codesign.log" || failed "signature does not verify"

    echo "--- signed host: $APP"
    codesign -dv "$APP" 2>&1 | grep -E '^(Identifier|TeamIdentifier|Signature|Authority)=' | head -4
    echo "--- effective entitlements:"
    codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p - 2>/dev/null
    DEFAULT_GROUP="$TEAM_ID.$BUNDLE_ID"
}

prepare_simulator() {
    xcrun simctl list devices booted 2>/dev/null | grep -q Booted || [ "$SIMULATOR" != "booted" ] ||
        not_executed "no booted iOS simulator (boot one or set ksm.apple.simulator)"
    otool -s __TEXT __entitlements "$KEXE" | grep -q __entitlements || failed "test binary has no __entitlements section"

    APP="$WORK/$EXECUTABLE.app"
    rm -rf "$APP"
    mkdir -p "$APP"
    cp "$KEXE" "$APP/$EXECUTABLE"
    info_plist "$APP/Info.plist" "$SIMULATOR_BUNDLE_ID" iPhoneSimulator
    codesign --force --sign - --timestamp=none "$APP" > "$WORK/codesign.log" 2>&1 || failed "ad-hoc codesign failed"
    xcrun simctl install "$SIMULATOR" "$APP" || not_executed "simctl install failed"

    echo "--- simulator host: $APP (ad-hoc signed, simulated entitlements)"
    echo "--- effective entitlements (__TEXT,__entitlements of the installed binary):"
    segedit "$APP/$EXECUTABLE" -extract __TEXT __entitlements "$WORK/entitlements.plist" 2>/dev/null || failed "cannot read the __entitlements section"
    plutil -p "$WORK/entitlements.plist"
    DEFAULT_GROUP="$SIMULATOR_TEAM.$SIMULATOR_BUNDLE_ID"
}

info_plist() {
    cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>$2</string>
    <key>CFBundleExecutable</key><string>$EXECUTABLE</string>
    <key>CFBundleName</key><string>$EXECUTABLE</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleSupportedPlatforms</key><array><string>$3</string></array>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>MinimumOSVersion</key><string>14.0</string>
    <key>UIDeviceFamily</key><array><integer>1</integer></array>
</dict>
</plist>
EOF
}

# Runs the host once with a test filter and extra KEY=VALUE environment.
# Sets LAST_COUNT; returns non-zero unless the runner reported success for
# more than zero tests.
launch() {
    local name="$1" filter="$2"
    shift 2
    local log="$WORK/$name.log" status
    local env=("KSM_KEYCHAIN_DEFAULT_GROUP=$DEFAULT_GROUP" "KSM_KEYCHAIN_SHARED_GROUP=$DEFAULT_GROUP.shared" "$@")
    echo "--- launch $name: --ktest_filter=$filter"
    if [ "$PLATFORM" = "macos" ]; then
        env "${env[@]}" "$APP/Contents/MacOS/$EXECUTABLE" "--ktest_filter=$filter" --ktest_logger=GTEST 2>&1 | tee "$log"
        status=${PIPESTATUS[0]}
    else
        # Another host with this bundle identifier may have been installed meanwhile.
        local installed
        installed="$(xcrun simctl get_app_container "$SIMULATOR" "$SIMULATOR_BUNDLE_ID" app 2>/dev/null)/$EXECUTABLE"
        cmp -s "$installed" "$APP/$EXECUTABLE" || failed "the installed simulator host is not this test binary"
        local simctl_env=() entry
        for entry in "${env[@]}"; do simctl_env+=("SIMCTL_CHILD_$entry"); done
        # simctl launch does not report the exit code: the runner's summary decides.
        env "${simctl_env[@]}" xcrun simctl launch --console-pty --terminate-running-process "$SIMULATOR" "$SIMULATOR_BUNDLE_ID" \
            "--ktest_filter=$filter" --ktest_logger=GTEST 2>&1 | tee "$log"
        status=0
    fi
    LAST_COUNT="$(sed -nE 's/^\[  PASSED  \] ([0-9]+) tests?\.\r?$/\1/p' "$log" | tail -1)"
    grep -q '^\[  FAILED  \]' "$log" && return 1
    [ "$status" -eq 0 ] && [ -n "$LAST_COUNT" ] && [ "$LAST_COUNT" -gt 0 ]
}

mkdir -p "$WORK"
[ -f "$KEXE" ] || failed "test binary $KEXE does not exist"
case "$PLATFORM" in
    macos) prepare_macos ;;
    ios-simulator) prepare_simulator ;;
    *) failed "unknown platform $PLATFORM" ;;
esac

summary=()
for mode in $MODES; do
    case "$mode" in
        tests)
            launch tests "$TEST_FILTER" || failed "DataProtection tests failed (see $WORK/tests.log)"
            summary+=("tests: $LAST_COUNT passed")
            ;;
        relaunch)
            namespace="relaunch-$(od -An -N8 -tu8 /dev/urandom | tr -d ' ')"
            ok=true
            for phase in create verify; do
                launch "relaunch-$phase" '*DataProtectionRelaunch*' "KSM_RELAUNCH_PHASE=$phase" "KSM_RELAUNCH_NAMESPACE=$namespace" || { ok=false; break; }
            done
            launch relaunch-cleanup '*DataProtectionRelaunch*' "KSM_RELAUNCH_PHASE=cleanup" "KSM_RELAUNCH_NAMESPACE=$namespace" || ok=false
            [ "$ok" = true ] || failed "relaunch persistence failed (see $WORK/relaunch-*.log)"
            summary+=("relaunch: create, verify, cleanup passed in 3 processes")
            ;;
        leftover)
            launch leftover '*DataProtectionLeftoverCheck*' || failed "test Keychain items remain (see $WORK/leftover.log)"
            summary+=("no test Keychain items left")
            ;;
        purge)
            launch purge '*DataProtectionPurge*' KSM_KEYCHAIN_PURGE=yes || failed "purge failed (see $WORK/purge.log)"
            summary+=("test Keychain items purged")
            ;;
        *) failed "unknown mode $mode" ;;
    esac
done
joined="$(printf '%s; ' "${summary[@]}")"
result "PASSED (${joined%; })"
