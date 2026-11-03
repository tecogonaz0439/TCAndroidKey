# BD-07 開発・ビルド・配布

| 項目 | 内容 |
|---|---|
| 文書番号 | TCSKE-BD-07 |
| 版数 | 1.3 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.3 (2026-11-03): 名称変更 (APK 名・環境変数名・release 鍵のファイル名、applicationId の維持) |
| 関連文書 | docs/CLOUD-BUILD.md、docs/LOCAL-BUILD-macOS.md |

## 1. 開発環境

| 環境 | 用途 | 構成 |
|---|---|---|
| クラウド | APK 作成、単体テスト、lint | Claude Code on the web。JDK 21 (既定イメージ)、Android SDK (セットアップスクリプトで `/opt/android-sdk` に導入) |
| ローカル | ビルド、実機デバッグ | macOS 27 + Android Studio (同梱 JBR 21)、Android SDK Platform 37 |
| 実機 | 動作確認 | Android 15+ 端末 (adb 接続) |

### 1.1 クラウド環境の設定項目

| 項目 | 設定 |
|---|---|
| Network access | `dl.google.com`, `maven.google.com`, `services.gradle.org`, `plugins.gradle.org`, `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `repo.maven.apache.org`, `repo1.maven.org` を許可 |
| Environment variables | `ANDROID_HOME=/opt/android-sdk`, `ANDROID_SDK_ROOT=/opt/android-sdk` |
| Setup script | `scripts/cloud/setup-android-sdk.sh` の内容 (cmdline-tools、`platform-tools`、`platforms;android-37.0`) |

Maven Central がクラウドの共有 IP に HTTP 429 を返すことがあるため、`gradle.properties` で依存取得のリトライを増やしている。

## 2. プロジェクト構成

| パス | 内容 |
|---|---|
| `settings.gradle.kts` | `:fido-core`, `:app` |
| `gradle/libs.versions.toml` | バージョンカタログ (TCSameuraDamMonitor-android と揃える) |
| `fido-core/` | Kotlin JVM モジュール (Java 21) |
| `app/` | Android アプリ (AGP 9 組み込み Kotlin + Compose コンパイラプラグイン) |
| `scripts/cloud/` | クラウド環境セットアップ |
| `scripts/cicd/` | `build-apk.sh`, `verify.sh`, `install-android.sh` |
| `scripts/test/` | PC 側試験スクリプト (python-fido2) |

## 3. ビルド

| コマンド | 内容 |
|---|---|
| `scripts/cicd/build-apk.sh` | debug APK を `build/cicd/apk/TCSecurityKeyEmulator-debug.apk` に出力し、SHA-256 を `build-info.txt` に記録 |
| `scripts/cicd/build-apk.sh --only release` | release APK (R8 による縮小・難読化) |
| `scripts/cicd/verify.sh` | `:fido-core:test` + `testDebugUnitTest` + `lintDebug` + `assembleDebug` |
| `scripts/cicd/install-android.sh --apk <path>` | adb で端末にインストールして起動 |

ビルド時に `copyLegalDocuments` (app/build.gradle.kts) が、利用規約・セキュリティポリシーの Markdown
(`docs/TERMS*.md`、`SECURITY.md`、`docs/SECURITY-ja.md`) を APK の `assets/legal/` へコピーする。

## 4. 署名

| 種別 | 鍵 | 方針 |
|---|---|---|
| debug | `app/debug.keystore` (リポジトリ同梱、パスワード `android`) | 開発専用の共通鍵。クラウド・ローカルのどちらでビルドしても同じ署名になり、**アンインストールせずに上書き更新** できる (アンインストールすると Keystore の鍵がすべて消えるため) |
| release | `keystore/tcsecuritykeyemulator-release.jks` (Git 管理外) | 環境変数 `TCSKE_STORE_PASSWORD` / `TCSKE_KEY_ALIAS` / `TCSKE_KEY_PASSWORD` で与える。未設定時は未署名 APK を出力 |

> debug 署名と release 署名は互いに上書きできない。テスト端末では原則 debug 版を使い続ける。

## 5. バージョン

| 項目 | 方針 |
|---|---|
| `versionName` | セマンティックバージョニング (`0.y.z` はテスト版) |
| `versionCode` | リリース毎に 1 ずつ増やす |
| ライブラリ | TCSameuraDamMonitor-android の `libs.versions.toml` に合わせて更新する |
| applicationId | `net.tecogonaz.tcandroidkey` で固定する。名称変更 (旧 TCAndroidKey → TCSecurityKeyEmulator) 後も変更しない。変えると別アプリ扱いとなり、上書き更新できず、登録済みの鍵も引き継げない |

## 6. 配布

PRE-05 (利用者は開発者・テスト担当者) のため、Google Play では配布しない。

| 方法 | 対象 |
|---|---|
| APK を直接インストール (adb / ファイル転送) | 開発者・テスト担当者の端末 |
| MDM (Android Enterprise 等) によるサイドロード配布 | 業務用のテスト端末 (GMS 非搭載端末を含む) |

## 7. ライセンス

Apache License 2.0。依存ライブラリは AndroidX / Jetpack Compose (Apache License 2.0)。
利用条件は [利用規約](../../TERMS-ja.md)、セキュリティ上の位置付けと脆弱性の報告は [セキュリティポリシー](../../SECURITY-ja.md) に定める。
