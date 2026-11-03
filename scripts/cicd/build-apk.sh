#!/bin/bash
set -euo pipefail

# Debug / Release APK を作成する (外部作用なし)。
# クラウドセッション・ローカル (macOS) の両方で使用する。
#   ANDROID_HOME 未設定時: クラウドは /opt/android-sdk、macOS は ~/Library/Android/sdk を探す。
#   JAVA_HOME 未設定時: macOS では Android Studio 同梱の JBR を使う。

if [[ -z "${ANDROID_HOME:-}" ]]; then
    for d in /opt/android-sdk "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        if [[ -d "$d" ]]; then export ANDROID_HOME="$d"; break; fi
    done
fi
if [[ -z "${JAVA_HOME:-}" && -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]]; then
    export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_NAME="TCSecurityKeyEmulator"
ONLY="debug"
OUTPUT_DIR="$PROJECT/build/cicd/apk"

usage() {
    cat <<'USAGE'
Usage: build-apk.sh [--only debug|release|both] [--output <dir>]

  --only VARIANT   debug (default), release, or both
  --output DIR     Output directory (default: <repo>/build/cicd/apk)

Release signing: place keystore/tcsecuritykeyemulator-release.jks and set
TCSKE_STORE_PASSWORD (and optionally TCSKE_KEY_ALIAS / TCSKE_KEY_PASSWORD).
USAGE
    exit 1
}

log() { echo "[build-apk] $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --only) ONLY="$2"; shift ;;
        --output) OUTPUT_DIR="$2"; shift ;;
        *) usage ;;
    esac
    shift
done

case "$ONLY" in debug|release|both) ;; *) usage ;; esac
if [[ -z "${ANDROID_HOME:-}" ]]; then
    log "Error: ANDROID_HOME is not set and no SDK was found. See docs/CLOUD-BUILD.md."
    exit 1
fi
log "ANDROID_HOME=$ANDROID_HOME"
mkdir -p "$OUTPUT_DIR"
cd "$PROJECT"

run_gradle() {
    local logfile="$OUTPUT_DIR/$1.log"
    log "Running ./gradlew $* (log: $logfile)"
    if ! ./gradlew --no-daemon "$@" >"$logfile" 2>&1; then
        log "Error: gradle $* failed. Last lines:"
        tail -40 "$logfile" >&2 || true
        exit 1
    fi
}

if [[ "$ONLY" == debug || "$ONLY" == both ]]; then
    run_gradle assembleDebug
    cp app/build/outputs/apk/debug/app-debug.apk "$OUTPUT_DIR/$APP_NAME-debug.apk"
    log "APK: $OUTPUT_DIR/$APP_NAME-debug.apk"
fi
if [[ "$ONLY" == release || "$ONLY" == both ]]; then
    run_gradle assembleRelease
    src=$(ls app/build/outputs/apk/release/*.apk | head -1)
    case "$src" in
        *unsigned*) dst="$OUTPUT_DIR/$APP_NAME-release-unsigned.apk" ;;
        *) dst="$OUTPUT_DIR/$APP_NAME-release.apk" ;;
    esac
    cp "$src" "$dst"
    log "APK: $dst"
fi

{
    echo "build date : $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "commit     : $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    for f in "$OUTPUT_DIR"/*.apk; do
        [[ -f "$f" ]] || continue
        if command -v sha256sum >/dev/null; then sha256sum "$f"; else shasum -a 256 "$f"; fi
    done
} >"$OUTPUT_DIR/build-info.txt"
log "Done. Artifacts in $OUTPUT_DIR"
