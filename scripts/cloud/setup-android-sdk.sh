#!/bin/bash
# Claude Code on the web (クラウドセッション) の環境「セットアップスクリプト」用。
# Android SDK コマンドラインツールと、ビルドに必要な SDK パッケージをインストールする。
#
# 前提:
#   - 環境のネットワークアクセスで dl.google.com / maven.google.com を許可していること
#     (docs/CLOUD-BUILD.md 参照)。
#   - JDK 21 はクラウドの既定イメージに含まれている。
#
# 冪等: 2 回目以降はインストール済みのものをスキップする。
set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
# https://developer.android.com/studio#command-line-tools-only の Linux 版のビルド番号
CMDLINE_TOOLS_BUILD="${CMDLINE_TOOLS_BUILD:-13114758}"
PLATFORM="${ANDROID_PLATFORM:-platforms;android-37.0}"

mkdir -p "$ANDROID_HOME/cmdline-tools"
if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
    tmp="$(mktemp -d)"
    curl -fsSL --retry 4 --retry-delay 2 -o "$tmp/cmdline-tools.zip" \
        "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip"
    unzip -q "$tmp/cmdline-tools.zip" -d "$tmp"
    rm -rf "$ANDROID_HOME/cmdline-tools/latest"
    mv "$tmp/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -rf "$tmp"
fi

SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKMANAGER" --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
"$SDKMANAGER" --sdk_root="$ANDROID_HOME" "platform-tools" "$PLATFORM"
# build-tools は AGP が必要なバージョンを自動ダウンロードする (ライセンス同意済みのため)。

# 以降のシェル (Claude のコマンド実行) でも ANDROID_HOME を使えるようにする。
cat > /etc/profile.d/android-sdk.sh <<PROFILE
export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="\$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin"
PROFILE

echo "Android SDK ready at $ANDROID_HOME"
