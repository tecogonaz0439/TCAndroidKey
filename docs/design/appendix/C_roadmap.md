# AP-C 既知の制約と今後の課題

本アプリはテスト用ツール (PRE-01) であり、物理キーの代替としない (PRE-02) ため、
以下の課題も「テスト対象 RP で必要になった場合に対応する」ことを基本とする。

## 1. 既知の制約

| ID | 制約 | 影響 | 回避策 |
|---|---|---|---|
| L-01 | clientPIN の一部の機能に非対応 (forcePINChange、setMinPINLength、getUVRetries。DD-01 §13.5) | PIN の最小の長さの変更・PIN の変更の強制を試験できない。PIN がブロックされても内蔵 UV は止まらない (CTAP 2.1 と異なる) | — |
| L-02 | CTAP 2.1 の一部のみ対応 (pinUvAuthToken、credProtect、credentialManagement。DD-01 §12) | authenticatorConfig、largeBlobs、enterprise attestation 等が使えない | — |
| L-03 | U2F (CTAP1) 非対応 | U2F 専用の古い RP で使えない | — |
| L-04 | 拡張 (largeBlob, minPinLength, credBlob 等) 非対応 (hmac-secret・credProtect は対応。DD-01 §11.2、§12.3) | 拡張を必須とする RP で使えない | — |
| L-05 | ES256 のみ | EdDSA / RS256 のみを指定する RP で使えない | RP の pubKeyCredParams に ES256 を含める |
| L-06 | NFC で本人確認前にかざすと 2 回かざす必要がある | 操作の手間 | 先に「本人確認して開始」を行う |
| L-07 | USB 非対応 (技術的に不可) | — | NFC / Bluetooth を使う |
| L-08 | Bluetooth HID は実験的 | ホスト環境により動作しない | NFC を使う |
| L-09 | macOS の Chrome は NFC (PC/SC) セキュリティキー非対応 | macOS ブラウザでの NFC 試験が限定される | python-fido2、Safari (要確認) |
| L-10 | 鍵のバックアップ・移行不可 | 端末の変更・アンインストールで鍵が失われる | テスト用アカウントを使う (PRE-04) |
| L-11 | ベンダーアテステーションなし | アテステーションを検証・制限する RP で登録できない | RP 側で自己アテステーション / none を許可する |
| L-12 | タッチ確認用のダミー登録を区別しない | CTAP 2.0 認証器にダミーの MakeCredential でタッチ確認するクライアントでは、ワンタイムが消費される (BD-04 §5 注。CTAP 2.1 に対応したクライアントは authenticatorSelection を使う見込み) | ワンタイム OFF にする / 再度本人確認する |
| L-13 | メタデータの巻き戻しを検出しない | 署名カウンタが戻り得る (BD-05 R-05) | — (想定外の攻撃者) |

## 2. 今後の課題 (候補)

| ID | 課題 | 概要 | 優先度 |
|---|---|---|---|
| F-01 | 互換性試験の実施と記録 | DD-10 §4 のマトリクスを埋め、BD-04 §5 を更新する | 高 |
| F-02 | clientPIN (PIN/UV Auth Protocol 2) | PIN 必須の RP・クライアントでの試験に対応する | 済 (2026-11-05。DD-01 §13) |
| F-03 | CTAP 2.1 (`FIDO_2_1`) | credProtect、credentialManagement、getPinUvAuthTokenUsingUvWithPermissions | 済 (2026-11-05。DD-01 §12) |
| F-04 | NFC での待機 (CTAP 2.1 の 0x9100 / NFCCTAP_GETRESPONSE) | 本人確認前にかざしても 1 回で完了できるようにする (クライアント対応の調査が必要) | 低 |
| F-05 | hmac-secret 拡張 | PRF 拡張を使う RP の試験に対応する | 済 (2026-11-05。DD-01 §11.2) |
| F-06 | U2F (CTAP1) | U2F の RP の試験に対応する | 低 |
| F-07 | 試験用の操作機能 | 署名カウンタの手動設定・UV フラグを立てない応答など、RP の異常系試験用の機能 (テスト用ツールとしての拡張) | 中 |
| F-08 | Android 依存部分の自動テスト | 認可判定は `AuthorizationGate` として JVM テスト済み (1.1)。残りは計装テスト (Keystore の読み込み失敗・保存失敗、HCE の切断・再接続、Bluetooth の登録解除) | 中 |
| F-09 | release ビルドでの R8 確認 | 縮小・難読化後の動作確認 | 中 |
| F-10 | 非公開の debug 署名鍵の選択 | 環境変数で非公開の署名鍵を指定でき、未指定時は共通 debug 鍵で署名する (BD-05 R-06)。切り替え時はアンインストールと再登録が必要 | 低 |
| F-11 | 外部レビュー指摘の実機確認 | DD-10 IT-24〜32 (切断・停止・同時要求・Bluetooth 復帰・TalkBack・文字サイズ・タッチ確認・メタデータ破損) | 高 |
