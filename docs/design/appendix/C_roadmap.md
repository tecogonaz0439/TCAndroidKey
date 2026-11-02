# AP-C 既知の制約と今後の課題

本アプリはテスト用ツール (PRE-01) であり、物理キーの代替としない (PRE-02) ため、
以下の課題も「テスト対象 RP で必要になった場合に対応する」ことを基本とする。

## 1. 既知の制約

| ID | 制約 | 影響 | 回避策 |
|---|---|---|---|
| L-01 | clientPIN 非対応 | RP / クライアントが PIN 設定済みの認証器を要求する場合に登録できない | RP の userVerification を `preferred` 等にする |
| L-02 | CTAP 2.1 非対応 (versions は `FIDO_2_0` のみ) | credProtect、credentialManagement、authenticatorConfig 等が使えない | — |
| L-03 | U2F (CTAP1) 非対応 | U2F 専用の古い RP で使えない | — |
| L-04 | 拡張 (hmac-secret, credProtect, largeBlob, minPinLength 等) 非対応 | 拡張を必須とする RP で使えない | — |
| L-05 | ES256 のみ | EdDSA / RS256 のみを指定する RP で使えない | RP の pubKeyCredParams に ES256 を含める |
| L-06 | NFC で本人確認前にかざすと 2 回かざす必要がある | 操作の手間 | 先に「本人確認して開始」を行う |
| L-07 | USB 非対応 (技術的に不可) | — | NFC / Bluetooth を使う |
| L-08 | Bluetooth HID は実験的 | ホスト環境により動作しない | NFC を使う |
| L-09 | macOS の Chrome は NFC (PC/SC) セキュリティキー非対応 | macOS ブラウザでの NFC 試験が限定される | python-fido2、Safari (要確認) |
| L-10 | 鍵のバックアップ・移行不可 | 端末の変更・アンインストールで鍵が失われる | テスト用アカウントを使う (PRE-04) |
| L-11 | ベンダーアテステーションなし | アテステーションを検証・制限する RP で登録できない | RP 側で自己アテステーション / none を許可する |

## 2. 今後の課題 (候補)

| ID | 課題 | 概要 | 優先度 |
|---|---|---|---|
| F-01 | 互換性試験の実施と記録 | DD-10 §4 のマトリクスを埋め、BD-04 §5 を更新する | 高 |
| F-02 | clientPIN (PIN/UV Auth Protocol 2) | PIN 必須の RP・クライアントでの試験に対応する | 中 |
| F-03 | CTAP 2.1 (`FIDO_2_1`) | credProtect、credentialManagement、getPinUvAuthTokenUsingUvWithPermissions | 中 |
| F-04 | NFC での待機 (CTAP 2.1 の 0x9100 / NFCCTAP_GETRESPONSE) | 本人確認前にかざしても 1 回で完了できるようにする (クライアント対応の調査が必要) | 低 |
| F-05 | hmac-secret 拡張 | PRF 拡張を使う RP の試験に対応する | 低 |
| F-06 | U2F (CTAP1) | U2F の RP の試験に対応する | 低 |
| F-07 | 試験用の操作機能 | 署名カウンタの手動設定・UV フラグを立てない応答など、RP の異常系試験用の機能 (テスト用ツールとしての拡張) | 中 |
| F-08 | Android 依存部分の自動テスト | `AuthSessionManager` の JVM テスト化、計装テスト (Keystore・HCE) | 中 |
| F-09 | release ビルドでの R8 確認 | 縮小・難読化後の動作確認 | 中 |
