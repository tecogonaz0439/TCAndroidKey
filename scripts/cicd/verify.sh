#!/bin/bash
set -euo pipefail

# 単体テスト (fido-core / app) + lint + debug ビルドを一括実行する (外部作用なし)。
if [[ -z "${ANDROID_HOME:-}" ]]; then
    for d in /opt/android-sdk "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        if [[ -d "$d" ]]; then export ANDROID_HOME="$d"; break; fi
    done
fi
if [[ -z "${JAVA_HOME:-}" && -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]]; then
    export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi

cd "$(dirname "$0")/../.."
./gradlew :fido-core:test testDebugUnitTest lintDebug assembleDebug "$@"
echo "verify passed"
