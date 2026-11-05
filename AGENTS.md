# AGENTS.md

AI コーディングエージェント (Claude Code、Codex など) と開発者が、このリポジトリの作業を引き継ぐための手引き。
詳細は各文書を参照し、ここには「作業前に知っておくべきこと」と「守るべき約束事」をまとめる。

## 1. プロジェクト概要

- **アプリ名**: セキュリティキーエミュレータ / Security Key Emulator
- **プロジェクト名・リポジトリ**: `TCSecurityKeyEmulator` (https://github.com/tecogonaz0439/TCSecurityKeyEmulator)。旧名 `TCAndroidKey`
- **applicationId / パッケージ**: `net.tecogonaz.tcsecuritykeyemulator`。旧名 `net.tecogonaz.tcandroidkey` とは別アプリ扱い
- **内容**: Android 端末を FIDO2 (CTAP 2.0 / 2.1) セキュリティキーとして動作させる。NFC (HCE) が主、Bluetooth HID は実験的、USB は技術的に不可
- **前提 (最重要)**: **FIDO / FIDO2 Web アプリケーションのテスト用ツール**であり、**YubiKey などの物理セキュリティキーの代替としない**。
  この前提は設計書 (PRE-01〜05)、利用規約、セキュリティポリシー、初回起動時のダイアログに明記している。機能追加時もこの前提を崩さない
- **技術スタック**: Android 15+ (minSdk 35、compileSdk / targetSdk 37)、Kotlin 2.4、Jetpack Compose (Material 3)、AGP 9.3、Gradle 9.5、JDK 21
- **UI の流用元**: [TCSameuraDamMonitor-android](https://github.com/tecogonaz0439/TCSameuraDamMonitor-android)。UI 部品・ビルド構成・バージョンを可能な限り合わせる
- **言語**: 利用者・設計書・コードコメントは日本語。README・利用規約・セキュリティポリシーは英語版と日本語版の両方を持つ

## 2. 現在の状態 (2026-11-05 時点)

- 作業ブランチ: `main` (リポジトリの既定ブランチ。旧名 `claude/friendly-sagan-ipwxxv`)
- 実装済み: CTAP 2.0 / 2.1 認証器、NFC / Bluetooth HID、Keystore 保管、認可ゲート、UI 一式、言語設定、利用規約・セキュリティポリシー表示、アイコン、
  PIN/UV Auth Protocol 1 / 2 (`fido.pin`)、hmac-secret・credProtect 拡張、内蔵 UV・PIN による pinUvAuthToken、credentialManagement、
  clientPIN (PIN の設定・変更・照合。アプリでは状態の表示と消去)
- 外部レビュー (ChatGPT Pro、対象 `ecd6e49`) の指摘 29 件は精査・対応済み。判定と不採用の理由は [review/FIX_PLAN.md](review/FIX_PLAN.md)
- 単体テスト 173 件 (fido-core 169、app 4) 全件成功、lint 指摘 0 件。python-fido2 による照合 (DD-10 CT-05、CT-07) 成功
- **未実施**:
  - 実機試験 ([DD-10](docs/design/detail/10_test-cases.md) の IT-01〜35、特に外部レビュー対応の IT-24〜32。hmac-secret・CTAP 2.1・clientPIN の CT-06・CT-08・CT-09、IT-36・IT-37)
  - 互換性マトリクスの記録 (DD-10 §4、[AP-C](docs/design/appendix/C_roadmap.md) F-01)
  - GitHub のリポジトリ名の変更 (所有者が手動で行う予定。文書・アプリ内の URL は新名称に変更済み)
- 今後の課題の候補は [AP-C](docs/design/appendix/C_roadmap.md) §2 (NFC の待機、試験用の操作機能、互換性試験など)

## 3. リポジトリ構成

```
fido-core/   FIDO2 プロトコル (Android 非依存の純 Kotlin/JVM)。JVM の単体テストで検証する
  cbor/      CTAP2 canonical CBOR
  ctap2/     Ctap2Authenticator (コマンド処理)、CredentialStore / AuthorizationPolicy / AuthorizationLease / KeepAlive、
             ClientPin (0x06、PIN・pinUvAuthToken)、PinStore、CredentialManagement (0x0A)、HmacSecret・CredProtect (拡張)
  pin/       PIN/UV Auth Protocol 1 / 2 (ECDH・HKDF・AES-CBC・HMAC)
  nfc/       ISO 7816-4 APDU (NfcCtapProcessor)
  hid/       CTAPHID (CtapHidProcessor)
  session/   AuthorizationGate (全トランスポート共有の認可判定)
app/         Android アプリ
  auth/      AuthSessionManager (AuthorizationGate の Android 側ラッパー)、UserVerifier (BiometricPrompt)
  keystore/  KeystoreCredentialStore、MetadataStore (AES-GCM で暗号化したメタデータ)、KeystorePinStore (PIN)
  nfc/       FidoHostApduService (HCE)
  bluetooth/ BluetoothHidAuthenticator (実験的)
  data/ domain/ ui/   設定・イベントログ・Compose 画面 (ui/document は利用規約等の表示)
scripts/     cloud/ (クラウドの SDK セットアップ)、cicd/ (build-apk / verify / install)、test/ (python-fido2 の試験)
docs/        設計書 (docs/design)、ビルド・テスト手順、利用規約 (TERMS*.md)、セキュリティポリシー (SECURITY-ja.md)
SECURITY.md  セキュリティポリシー (英語。GitHub が表示する)
review/      外部レビューの依頼文と対応記録 (履歴として旧名のまま残す)
```

## 4. ビルドとテスト

前提: JDK 21 (Android Studio 同梱の JBR で可)、Android SDK Platform 37。`local.properties` (SDK のパス) は Git 管理外。

| 目的 | コマンド |
|---|---|
| 単体テスト + lint + debug ビルド (変更後は必ず実行) | `scripts/cicd/verify.sh` (= `./gradlew :fido-core:test testDebugUnitTest lintDebug assembleDebug`) |
| debug APK の作成 | `scripts/cicd/build-apk.sh` → `build/cicd/apk/TCSecurityKeyEmulator-debug.apk` |
| 端末へのインストールと起動 | `scripts/cicd/install-android.sh [--apk <path>]` |
| fido-core のみ | `./gradlew :fido-core:test` |
| python-fido2 による応答形式の照合 (実機不要) | [docs/TESTING.md](docs/TESTING.md) §7 (`TCSKE_INTEROP_OUT=…` → `scripts/test/verify_interop_vectors.py`) |
| PC/SC リーダー経由の実機試験 | `scripts/test/fido2_nfc_test.py` (python-fido2 2.0.0) |

- 完了の基準: テスト全件成功、**lint 指摘 0 件** (現状 0 件を維持する)。
- Maven Central が HTTP 429 を返すことがある。`gradle.properties` に再試行の設定がある。失敗したら時間をおいて再実行する。
- クラウド環境での構築は [docs/CLOUD-BUILD.md](docs/CLOUD-BUILD.md)、macOS は [docs/LOCAL-BUILD-macOS.md](docs/LOCAL-BUILD-macOS.md)。
- 実機の NFC 処理をデバッガで止めると通信がタイムアウトする。`adb logcat -s TCSecurityKeyEmulator` を使う。

## 5. 守るべき約束事 (変更前に必ず確認)

### 5.1 セキュリティ・認可 (設計: [DD-05](docs/design/detail/05_state-machines.md) §2、[BD-05](docs/design/basic/05_security.md))

- 認証を受け付けるのは「アプリが前面表示中」かつ「本人確認後の受付時間内」のみ。判定は `AuthorizationGate` に集約し、
  トランスポートや画面に個別の判定を追加しない。
- 判定とワンタイムの予約は同じロック内で行う。明示的な停止・前面離脱では epoch を進めて全 Lease を失効させ、
  ワンタイムの「消費」では失効させない (GetNextAssertion の継続のため)。単純な `isArmed()` の追加で済ませない。
- `Ctap2Authenticator` は、鍵の生成・署名の直前と応答の直前に Lease と取消トークンを確認し、すべての経路で `lease.complete()` を呼ぶ。
- pinUvAuthToken (CTAP 2.1) があっても、登録・認証・資格情報の管理のたびに受付ゲートの認可を得る。トークンの発行・資格情報の管理・
  silent assertion ではワンタイムを消費しない。トークンは発行時の Lease・セッションの世代に結び付ける (DD-01 §12、DD-05 §2.5)。
- PIN の照合・設定・変更は受付ゲートの認可の後に行う (受付外では試行回数を減らさない)。PIN を読み込めない場合は未設定として扱わない (DD-01 §13)。
- `Ctap2Authenticator.process` と CTAPHID のワーカーは例外をすべて捕捉する (Kotlin では検査例外も素通りし、ワーカーで落ちるとアプリが終了する)。
- NFC は接続世代で古い応答を破棄する (`FidoHostApduService`)。CTAPHID の取消は要求ごとの操作 (トークン) で扱う。
- Google Play 開発者サービスを使わない。**INTERNET 権限を追加しない** (利用規約 第 4 条で通信しないと約束している)。
- logcat には RP ID・ユーザー名・Bluetooth ホスト名を出さない (`EventLogRepository.log` の `logcatMessage`)。イベントログはメモリのみ。
- `FLAG_SECURE`、バックアップ除外 (`allowBackup=false`、data extraction rules) を外さない。
- 削除・保護を弱める設定変更 (PIN の消去、ワンタイム OFF、生体認証のみ OFF、リセット許可 ON) には本人確認を要求する。
- メタデータを読み込めない場合は空として扱わず UNAVAILABLE にする (上書きしない)。更新は保存成功後にキャッシュへ反映する。

### 5.2 識別子 (変えると既存の端末で鍵が使えなくなる)

- applicationId / パッケージ `net.tecogonaz.tcsecuritykeyemulator`、Keystore のエイリアス (`fido_cred_<id>`、`fido_hmac_<id>`、`tcsecuritykeyemulator_metadata_v1`、`tcsecuritykeyemulator_pin_v1`)、ファイル名 (`credentials.bin`、`pin.bin`)、
  SharedPreferences 名 (`settings`) と各キー、AAGUID (`523283ca-3c2c-48b5-8bff-a722f900e190`) は変更しない。
- `app/debug.keystore` は上書き更新のために意図的に公開・管理している (残存リスク R-06)。release 用の鍵は Git に入れない。

### 5.3 プロトコル

- CTAP 2.0 / 2.1 (`FIDO_2_0`、`FIDO_2_1`)、ES256 のみ、ユーザー検証は内蔵 UV と clientPIN。拡張は credProtect・hmac-secret。pinUvAuthProtocols は `[2, 1]`
  (2.0 のクライアントのため Protocol 1 を残す)。GetInfo に未対応の機能 (clientPin 等) を広告しない。
- 2.1 の判断 (DD-01 §12.5): `makeCredUvNotRqd: true` とし `PUAT_REQUIRED` を返さない、MakeCredential の `up: true` を受け付ける。
- メタデータの JSON に項目を足すときは任意項目とし、ない場合は既定値で読む (既存の端末の credentials.bin を読めるようにする)。
- 外部レビューで「不採用」と判断した修正案 (MakeCredential の `up:true` 拒否、CBOR のキー順序検証、NFC P1/P2 の厳格検証、
  Bluetooth の transports 変更など) は、理由が [review/FIX_PLAN.md](review/FIX_PLAN.md) にある。蒸し返す場合は理由を確認する。

## 6. コーディング規約

- 新規ファイルの先頭に SPDX ヘッダー (`SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>` / `SPDX-License-Identifier: Apache-2.0`)。
- コメント・KDoc は日本語。識別子とプロトコル用語は英語のまま。
- DI フレームワーク・Room・GMS は使わない (手動 DI: `AppContainer`)。プロトコル処理は fido-core に置き、JVM テストを付ける。
- 文字列は `values/strings.xml` (英語) と `values-ja/strings.xml` (日本語) の**両方**に追加する。件数を含む文字列は `plurals`。
- UI 部品は TCSameuraDamMonitor の部品 (`ui/common`) を優先して使う。

## 7. ドキュメントの更新ルール

- **コードを変えたら設計書も同じコミットで直す。** 設計書の索引は [docs/design/README.md](docs/design/README.md)。
  - 変更した文書の表の「版数」を上げ、「改訂」行に日付と内容を書く。大きな変更は docs/design/README.md の改訂履歴にも記載する。
  - 要件 (FR / NFR / SEC)、試験 (UT / CT / IT) の ID を追加・更新し、DD-10 §5 の対応表も直す。
  - Mermaid 図は描画できること、相対リンクが切れていないことを確認する。
- 利用規約・セキュリティポリシーを変える場合は**日本語版と英語版の両方**を直し、最終更新日を更新する (相違時は日本語版が優先)。
  本文はビルド時に `copyLegalDocuments` で APK に取り込まれる (コードに本文を書かない)。`LegalDocumentTest` がリンク切れを検出する。
- README.md (英語) と README-ja.md (日本語) は内容を揃える。
- 試験手順は [docs/TESTING.md](docs/TESTING.md) のチェックリストにも反映する。

## 8. Git の運用

- ビルド生成物 (APK を含む) はコミットしない (`.gitignore` 参照)。APK は `scripts/cicd/build-apk.sh` で作る。
- コミットメッセージは英語。1 行目に要約、本文に変更の理由と内容。
- コミットの作者: `tecogonaz <tecogonaz@kusugami-lab.net>`。

## 9. 参照

| 文書 | 内容 |
|---|---|
| [README.md](README.md) / [README-ja.md](README-ja.md) | 概要・使い方 |
| [docs/design/](docs/design/README.md) | 設計書一式 (基本設計 BD-01〜09、詳細設計 DD-01〜10、付録) |
| [docs/TESTING.md](docs/TESTING.md) | 実機試験の手順・チェックリスト |
| [docs/TERMS-ja.md](docs/TERMS-ja.md) / [docs/TERMS.md](docs/TERMS.md) | 利用規約 |
| [docs/SECURITY-ja.md](docs/SECURITY-ja.md) / [SECURITY.md](SECURITY.md) | セキュリティポリシー |
| [review/FIX_PLAN.md](review/FIX_PLAN.md) | 外部レビューの判定と対応 |
