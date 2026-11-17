#!/usr/bin/env bash
# Stage 11: apply real Apple identifiers to the iOS project.
#
# Replaces the committed placeholders with the real values from your
# Apple Developer account, consistently across the pbxproj, all
# entitlements/Info.plists and the Swift sources that mirror them:
#
#   TEAMIDPLACEHOLDER                 -> your 10-character Team ID
#   group.com.kosherguard.shared      -> your registered App Group
#   com.kosherguard.app[.*]           -> your bundle ID prefix (optional)
#   pir/issuer.kosherguard.example.com -> your PIR hosts (optional)
#
# Default is DRY RUN (prints the replacements it would make). Pass
# --write to apply. Run from anywhere; it edits the repo it lives in.
# After --write it re-runs tools/validate-ios-project.py.
#
# Usage:
#   tools/apply-apple-team-id.sh --team-id ABCDE12345
#   tools/apply-apple-team-id.sh --team-id ABCDE12345 \
#       --bundle-prefix com.myorg.kosherguard \
#       --app-group group.com.myorg.kosherguard.shared \
#       --pir-server pir.example.com --pir-issuer issuer.example.com \
#       --write
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

TEAM_ID=""
BUNDLE_PREFIX="com.kosherguard"
APP_GROUP="group.com.kosherguard.shared"
PIR_SERVER=""
PIR_ISSUER=""
WRITE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --team-id) TEAM_ID="$2"; shift 2 ;;
        --bundle-prefix) BUNDLE_PREFIX="$2"; shift 2 ;;
        --app-group) APP_GROUP="$2"; shift 2 ;;
        --pir-server) PIR_SERVER="$2"; shift 2 ;;
        --pir-issuer) PIR_ISSUER="$2"; shift 2 ;;
        --write) WRITE=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if ! printf '%s' "$TEAM_ID" | grep -qE '^[A-Z0-9]{10}$'; then
    echo "error: --team-id must be the 10-character Apple Team ID " \
        "(A-Z, 0-9), got '$TEAM_ID'" >&2
    exit 2
fi

FILES=(
    ios/Configuration/App.entitlements
    ios/Configuration/FilterExtension.entitlements
    ios/Configuration/FilterControlExtension.entitlements
    ios/Configuration/DNSProxyExtension.entitlements
    ios/Configuration/URLFilterExtension.entitlements
    ios/Configuration/App-Info.plist
    ios/KosherGuard.xcodeproj/project.pbxproj
    ios/Sources/URLFilter/KeychainCredentialStore.swift
    ios/Sources/URLFilter/FilterRuleStore.swift
    ios/Sources/URLFilter/URLFilterConfiguration.swift
)

apply_file() {
    local rel="$1"
    local f="$ROOT/$rel"
    [ -f "$f" ] || return 0
    grep -q 'TEAMIDPLACEHOLDER\|group\.com\.kosherguard\.shared\|com\.kosherguard\.app\|kosherguard\.example\.com' "$f" || return 0
    # Identifiers are [A-Za-z0-9.-] only, so no sed-delimiter or & hazards.
    local tmp="$f.stage11.tmp"
    sed \
        -e "s|TEAMIDPLACEHOLDER|${TEAM_ID}|g" \
        -e "s|group\.com\.kosherguard\.shared|${APP_GROUP}|g" \
        -e "s|com\.kosherguard\.app|${BUNDLE_PREFIX}.app|g" \
        ${PIR_SERVER:+-e "s|pir\.kosherguard\.example\.com|${PIR_SERVER}|g"} \
        ${PIR_ISSUER:+-e "s|issuer\.kosherguard\.example\.com|${PIR_ISSUER}|g"} \
        "$f" > "$tmp"
    mv "$tmp" "$f"
    echo "  updated $rel"
}

echo "Team ID:        $TEAM_ID"
echo "Bundle prefix:  $BUNDLE_PREFIX (app becomes ${BUNDLE_PREFIX}.app)"
echo "App group:      $APP_GROUP"
echo "PIR server:     ${PIR_SERVER:-(unchanged placeholder)}"
echo "PIR issuer:     ${PIR_ISSUER:-(unchanged placeholder)}"

if [ "$WRITE" -eq 0 ]; then
    echo
    echo "DRY RUN - the following replacements would be applied:"
    for rel in "${FILES[@]}"; do
        f="$ROOT/$rel"
        [ -f "$f" ] || continue
        hits=$(grep -c 'TEAMIDPLACEHOLDER\|group\.com\.kosherguard\.shared\|com\.kosherguard\.app\|kosherguard\.example\.com' "$f" || true)
        [ "$hits" -gt 0 ] && echo "  $rel: $hits line(s) would change"
    done
    echo
    echo "Re-run with --write to apply. Then commit and let CI compile."
    exit 0
fi

for rel in "${FILES[@]}"; do
    apply_file "$rel"
done

echo
echo "Re-running static validation..."
python3 "$ROOT/tools/validate-ios-project.py"
echo
echo "Done. Review with: git -C $ROOT diff ios/"
