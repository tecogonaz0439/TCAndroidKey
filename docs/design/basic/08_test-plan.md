# BD-08 テスト計画

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-BD-08 |
| 版数 | 1.0 |
| 作成日 | 2026-11-02 |
| 関連文書 | DD-10 テスト仕様、docs/TESTING.md |

## 1. 方針

- プロトコル処理 (`fido-core`) は、JVM 上の単体テストで仕様どおりの入出力と署名の正当性を検証する。
  JCA のソフトウェア鍵による `InMemoryCredentialStore` を用い、WebAuthn クライアント相当の署名検証まで行う。
- Android 依存部分 (Keystore、HCE、BiometricPrompt、Bluetooth) は、実機試験で検証する。
- 動作確認はローカル環境で行う (クラウドでは APK 作成と単体テスト・lint のみ)。
- 本アプリはテスト用ツール (PRE-01) のため、試験にはテスト用 RP / テスト用アカウントのみを使い、本番サービスを使わない (PRE-02)。

## 2. テストレベル

| レベル | 対象 | 実施環境 | 実施タイミング | 合格基準 |
|---|---|---|---|---|
| UT 単体テスト | `fido-core` (CBOR、CTAP2、APDU、CTAPHID) | クラウド / ローカル (`./gradlew :fido-core:test`) | コミット毎 | 全件成功 |
| ST 静的検査 | `app` (Android lint) | クラウド / ローカル (`lintDebug`) | コミット毎 | エラー 0 件 |
| CT CTAP 結合試験 | 実機 + PC/SC リーダー + python-fido2 | ローカル | APK 更新毎 | GetInfo・登録・認証・署名検証が成功 |
| IT 実機試験 | 実機 + ブラウザ + テスト用 RP | ローカル | APK 更新毎 (主要項目)、リリース前 (全項目) | DD-10 の期待結果どおり |
| CP 互換性試験 | クライアント OS / ブラウザ / 接続方式の組み合わせ | ローカル | リリース前 | 結果を互換性マトリクスに記録 |

## 3. 試験環境

| ID | 環境 | 用途 |
|---|---|---|
| ENV-01 | Windows 11 + Sony RC-S300/P + Edge / Chrome / python-fido2 | NFC (主) |
| ENV-02 | macOS 27 + Sony RC-S300/P + python-fido2 / Safari | NFC |
| ENV-03 | Android 15+ (NFC、別端末) + Chrome | NFC (端末同士) |
| ENV-04 | Windows 11 / macOS 27 + Bluetooth | Bluetooth HID (実験的) |
| ENV-05 | 認証器端末: Android 15+、StrongBox 搭載機・非搭載機 (可能なら両方) | 全試験 |

テスト用 RP として https://webauthn.io など公開のデモサイト、または開発中の Web アプリのテスト環境を用いる。

## 4. 不具合の記録

試験で不具合を検出した場合は、次の情報を記録する。

- 試験 ID、環境 ID、APK のコミットハッシュ (`build-info.txt`)
- アプリのイベントログ (SC-03。RP ID・ユーザー名を含む)、`adb logcat -s TCAndroidKey` の出力 (コマンドと結果のみ)
- クライアント側のエラー表示 (ブラウザのメッセージ・スクリーンショット)
