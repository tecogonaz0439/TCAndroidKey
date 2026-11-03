# BD-04 外部インターフェース

| 項目 | 内容 |
|---|---|
| 文書番号 | TCSKE-BD-04 |
| 版数 | 1.1 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.1 (2026-11-02): 外部レビュー対応 (GET RESPONSE の CLA、拡張長応答、互換性の注記)。`review/FIX_PLAN.md` |
| 関連文書 | DD-01 CTAP2、DD-02 NFC、DD-03 Bluetooth HID |

## 1. インターフェース一覧

| ID | インターフェース | 方式 | 状態 | 関連要件 |
|---|---|---|---|---|
| IF-01 | NFC | ISO/IEC 14443-4 (HCE) 上の ISO 7816-4 APDU、FIDO NFC プロトコル | 済 | FR-01 |
| IF-02 | Bluetooth | Bluetooth Classic HID Device プロファイル上の CTAPHID | 実験 | FR-02 |
| IF-03 | USB | なし (§4) | 否 | FR-03 |
| IF-04 | OS 本人確認 | BiometricPrompt (BIOMETRIC_STRONG / DEVICE_CREDENTIAL) | 済 | FR-11 |
| IF-05 | OS 鍵保管 | Android Keystore (AndroidKeyStore プロバイダ) | 済 | NFR-04 |

## 2. 上位プロトコル (共通)

全トランスポートで **CTAP 2.0** (FIDO Client to Authenticator Protocol) のコマンドを処理する。

| 項目 | 内容 |
|---|---|
| バージョン | `FIDO_2_0` |
| 対応コマンド | GetInfo (0x04)、MakeCredential (0x01)、GetAssertion (0x02)、GetNextAssertion (0x08)、Reset (0x07)、Selection (0x0B) |
| 非対応 | ClientPIN (0x06)、CredentialManagement (0x0A)、CTAP1/U2F |
| アルゴリズム | ES256 (COSE -7、ECDSA P-256 / SHA-256) |
| ユーザー検証 | 内蔵 UV (`uv: true`)。PIN は使わない |
| アテステーション | `none` (既定) / `packed` 自己アテステーション |
| AAGUID | `523283ca-3c2c-48b5-8bff-a722f900e190` |

詳細は DD-01。

## 3. トランスポート別の方式

### 3.1 NFC (IF-01)

| 項目 | 内容 |
|---|---|
| 方式 | Android の HCE。AID `A0000006472F0001` (FIDO) を登録 (category `other`) |
| 応答する条件 | 端末ロック解除中 (`requireDeviceUnlock`)、画面オン、アプリ前面表示中、本人確認後の受付時間内 |
| 応答しない場合 | SELECT に `6A82` (ファイルなし) を返し、FIDO アプレットが存在しないように振る舞う |
| 対応 APDU | SELECT、NFCCTAP_MSG (CLA 80/90, INS 10)、GET RESPONSE (CLA 00 / 80, INS C0)、短い APDU / 拡張長 APDU、コマンドチェイニング、短い APDU へのレスポンスチェイニング (拡張長 APDU には応答全体を一度に返す) |
| 試験するクライアント | Windows 11 + RC-S300/P (Windows WebAuthn API)、macOS 27 + RC-S300/P (python-fido2 等)、Android 15+ (Chrome) |

### 3.2 Bluetooth HID (IF-02、実験的)

| 項目 | 内容 |
|---|---|
| 方式 | `BluetoothHidDevice` で FIDO HID デバイス (Usage Page `0xF1D0`, Usage `0x01`, 64 バイト入出力レポート) を登録 |
| 接続 | PC 側から本端末を Bluetooth デバイスとしてペアリング・接続する |
| 特徴 | 通信中に待機できるため、未確認の場合はその場で本人確認ダイアログを表示し、KEEPALIVE を送りながら最大 30 秒待つ |
| 制約 | ホスト OS / ブラウザが Bluetooth 接続の FIDO HID デバイスを扱うかは環境に依存し、動作を保証しない。端末側 Bluetooth スタックの HID Device プロファイル対応にも依存する |

## 4. USB (IF-03) を非対応とする理由

- PC から FIDO セキュリティキーとして認識されるには、端末が **USB HID デバイス** (FIDO usage page) として列挙される必要がある。
- Android の USB デバイスモードの機能構成 (configfs / USB ガジェット) はシステム権限で制御され、
  一般アプリは root 化なしに HID ガジェットを追加できない。
- アプリから利用できる USB Accessory (AOA) モードは HID ではなく、OS の WebAuthn 実装からは使えない。

以上より、要件 FR-03 は「技術的に対応不可」と判断した。

## 5. 互換性の想定

| クライアント | 接続 | 想定 | 備考 |
|---|---|---|---|
| Windows 11 + Edge / Chrome | NFC (RC-S300/P) | 利用可の想定 | Windows の WebAuthn API が PC/SC リーダー経由の NFC セキュリティキーを扱う。RC-S300 には Sony の PC/SC ドライバーが必要 |
| Windows 11 + python-fido2 2.0.0 (低水準 `Ctap2`) | NFC (RC-S300/P) | 利用可の想定 | CTAP レベルの確認用 (`scripts/test/fido2_nfc_test.py`)。応答形式は実機なしで python-fido2 により検証済み (DD-10 CT-05) |
| python-fido2 2.0.0 (高水準 `Fido2Client`) | NFC | UV required は利用不可の見込み | 内蔵 UV の前に PIN/UV プロトコルを選択し、`pinUvAuthProtocols` のない認証器で例外になる (クライアント側の制約。DD-10 §4 注 1) |
| libfido2 系 (`fido2-token` 等) | NFC (PC/SC) | 利用可の想定 | GET RESPONSE に `80 C0` を使う (1.1 で対応) |
| macOS 27 + Chrome | NFC | 利用不可 | macOS の Chrome は PC/SC 経由の NFC セキュリティキーに非対応 |
| macOS 27 + Safari | NFC | 未確認 | スマートカードリーダー経由の NFC セキュリティキーを扱える可能性がある |
| macOS 27 + python-fido2 | NFC (RC-S300/P) | リーダー認識次第 | macOS 標準 CCID ドライバーが RC-S300 に対応しているか要確認 |
| Android 15+ + Chrome | NFC (端末同士) | 利用可の想定 | クライアント側は OS / Chrome の FIDO 実装を使う |
| Windows / macOS + ブラウザ | Bluetooth HID | 未確認 (実験) | HID として認識されることと、FIDO クライアントが列挙して使えることは別。libfido2 の標準バックエンドは USB 以外の HID を列挙しない場合がある |

実際の結果は試験 (DD-10) で、クライアントの版と API 層を含めて記録する。

> **注 (タッチ確認用の登録)**: CTAP 2.0 の認証器に対して、Chromium 系の FIDO 実装は認証器の選択のために
> ダミーの MakeCredential でタッチを確認することがある。本アプリはこれを通常の登録として扱うため、ワンタイム ON では
> 受付を消費し、後続の本来の要求が失敗し得る。今回の試験環境 (Windows は webauthn.dll、Android は Google Play 開発者サービス、
> macOS の Chrome は NFC 非対応) では該当経路を通らない見込みだが、実機で確認する (DD-10 IT-31)。
> ダミー RP 名による特別扱いは、相手が同じ値を送れるため行わない。
