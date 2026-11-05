# クラウド (Claude Code on the web) でのビルド環境

クラウドセッションでは **APK の作成のみ** を行い、インストール・デバッグはローカルの Android 端末で行う。

## 1. 確認結果

| 時点 | 結果 |
|---|---|
| 初回 (既定のネットワークポリシー) | `dl.google.com` が拒否 (403) され、Android SDK と Google Maven (AndroidX・AGP) を取得できず `app` はビルド不可。`fido-core` のみコンテナ内の Kotlin コンパイラでビルド・テスト |
| 2.1〜2.3 の設定後 | SDK インストール、`./gradlew :fido-core:test assembleDebug lintDebug` すべて成功 (テスト 122 件成功 (fido-core 118 件、app 4 件。2026-11-05 時点)、lint 指摘 0) |

> **Maven Central の HTTP 429**: クラウドの共有 IP では `repo.maven.apache.org` が 429 (Too Many Requests) を返すことがある。
> `gradle.properties` で Gradle の依存取得リトライを 12 回・初期待機 3 秒に増やしてある。
> それでも失敗した場合は、取得済みの依存はキャッシュされるため、少し待って同じコマンドを再実行すれば先へ進む。

## 2. 環境設定 (ユーザー側で実施)

claude.ai/code のセッション画面タイトルバーの **クラウド環境メニュー → Edit** で、使用する環境を編集する。
(手順の詳細: https://code.claude.com/docs/en/cloud-environments#network-access)

### 2.1 Network access

アクセスレベルを **Limited** (アプリが古い場合は **Custom**) にし、**Allowed domains** に次を追加する。
「Allow package managers」(既定のパッケージマネージャー一覧を含める) のチェックは **入れたまま** にする。

```
dl.google.com
maven.google.com
services.gradle.org
plugins.gradle.org
github.com
objects.githubusercontent.com
release-assets.githubusercontent.com
repo.maven.apache.org
repo1.maven.org
```

> Maven Central (`repo.maven.apache.org`) は既定のパッケージマネージャー一覧に含まれていることが多いが、念のため列挙している。
> 429 (レート制限) が出た場合は時間をおいて再実行する。

### 2.2 Environment variables

```
ANDROID_HOME=/opt/android-sdk
ANDROID_SDK_ROOT=/opt/android-sdk
```

### 2.3 Setup script

次の内容をそのまま **Setup script** 欄に貼り付ける (リポジトリの `scripts/cloud/setup-android-sdk.sh` と同じ内容)。
セットアップスクリプトは環境変数を読めないため、パスはスクリプト内の既定値 (`/opt/android-sdk`) を使う。

```bash
#!/bin/bash
set -euo pipefail
ANDROID_HOME=/opt/android-sdk
CMDLINE_TOOLS_BUILD=13114758
mkdir -p "$ANDROID_HOME/cmdline-tools"
if [ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]; then
    tmp="$(mktemp -d)"
    curl -fsSL --retry 4 --retry-delay 2 -o "$tmp/cmdline-tools.zip" \
        "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip"
    unzip -q "$tmp/cmdline-tools.zip" -d "$tmp"
    mv "$tmp/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
    rm -rf "$tmp"
fi
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
yes | "$SDKMANAGER" --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
"$SDKMANAGER" --sdk_root="$ANDROID_HOME" "platform-tools" "platforms;android-37.0"
cat > /etc/profile.d/android-sdk.sh <<PROFILE
export ANDROID_HOME="$ANDROID_HOME"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="\$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin"
PROFILE
```

- build-tools は AGP が必要なバージョンを初回ビルド時に自動ダウンロードする (ライセンス同意済みのため)。
- cmdline-tools のビルド番号が古くなった場合は https://developer.android.com/studio#command-line-tools-only の
  Linux 版ファイル名の番号に差し替える。
- 新しいセッションから設定が反映される。

## 3. クラウドでの APK 作成

設定後に新しいセッションを開始し、Claude に次のように依頼する。

> `scripts/cicd/build-apk.sh` で debug APK を作成し、APK ファイルを送ってください。

スクリプトは `build/cicd/apk/TCSecurityKeyEmulator-debug.apk` と `build-info.txt` (SHA-256) を出力する。
Claude がファイルとして送付した APK を claude.ai / Claude アプリからダウンロードし、ローカルでインストールする
(`docs/TESTING.md` の「インストール」参照)。

- 単体テストのみ: `./gradlew :fido-core:test`
- lint + テスト + ビルド: `scripts/cicd/verify.sh`

### 署名について

`app/debug.keystore` は開発専用の共通デバッグ署名鍵 (秘密ではない) で、クラウド・ローカルどちらでビルドしても
同じ署名になる。これにより端末上のアプリを **アンインストールせずに上書き更新** できる。
(アンインストールすると Android Keystore 内の FIDO 鍵がすべて消え、登録済みサービスにログインできなくなる。)

リリース APK を作る場合は `keystore/tcsecuritykeyemulator-release.jks` (Git 管理外) を用意し、
`TCSKE_STORE_PASSWORD` 等を環境変数で与えて `scripts/cicd/build-apk.sh --only release` を実行する。
