#!/bin/bash
set -euo pipefail

# ローカル PC に接続した Android 端末へ Debug APK をインストールする。
# クラウドでビルドした APK を使う場合は --apk でパスを指定する。
#
#   scripts/cicd/install-android.sh --apk ~/Downloads/TCAndroidKey-debug.apk
#   scripts/cicd/install-android.sh --build     (ローカルでビルドしてからインストール)

if [[ -z "${ANDROID_HOME:-}" ]]; then
    for d in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" /opt/android-sdk; do
        if [[ -d "$d" ]]; then export ANDROID_HOME="$d"; break; fi
    done
fi
export PATH="${ANDROID_HOME:-}/platform-tools:$PATH"

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
APK="$PROJECT/app/build/outputs/apk/debug/app-debug.apk"
SERIAL=""
BUILD="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apk) APK="$2"; shift ;;
        --device) SERIAL="$2"; shift ;;
        --build) BUILD="true" ;;
        *) echo "Usage: install-android.sh [--apk PATH] [--device SERIAL] [--build]" >&2; exit 1 ;;
    esac
    shift
done

if [[ "$BUILD" == "true" ]]; then
    (cd "$PROJECT" && ./gradlew assembleDebug)
fi
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }

ADB=(adb)
[[ -n "$SERIAL" ]] && ADB+=(-s "$SERIAL")
"${ADB[@]}" install -r "$APK"
"${ADB[@]}" shell am start -n net.tecogonaz.tcandroidkey/.MainActivity
echo "Installed and launched. Watch logs with: adb logcat -s TCAndroidKey"
