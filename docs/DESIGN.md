# TCAndroidKey 設計書

Android 端末そのものを YubiKey のような **FIDO2 (CTAP2) 物理セキュリティキー** として振る舞わせ、
PC (Windows / macOS) や他の Android 端末での WebAuthn 認証 (パスキー / 2 要素認証) に使うアプリ。

## 1. 要件と対応方針

| 要件 | 方針 | 状態 |
|---|---|---|
| NFC 接続 (主ターゲット) | HCE (Host-based Card Emulation) で FIDO アプレット (AID `A0000006472F0001`) をエミュレート。CTAP 2.0 over NFC (ISO 7816-4 APDU) | 実装済み |
| Bluetooth 接続 (可能なら) | Android の `BluetoothHidDevice` (HID Device プロファイル) で FIDO HID デバイス (usage page `0xF1D0`) として振る舞い、CTAPHID を実装 | 実装済み・**実験的** |
| USB 接続 (可能なら) | Android アプリは root なしに USB HID ガジェットになれない (configfs はシステム権限)。AOA (Accessory モード) は HID ではないため OS の WebAuthn から使えない | **非対応** (技術的に不可) |
| 秘密鍵は OS 標準キーストア (TEE / StrongBox) | `AndroidKeyStore` で EC P-256 鍵をクレデンシャル毎に生成。StrongBox 搭載端末では StrongBox を優先 (設定で変更可) | 実装済み |
| 全キー削除・個別削除 | アプリ画面から個別削除・全削除 (いずれも本人確認必須)。設定で許可した場合のみ OS からの authenticatorReset も受け付ける | 実装済み |
| Android 15+ / Kotlin 2 / Jetpack Compose | minSdk 35, compileSdk/targetSdk 37, Kotlin 2.4, Compose BOM 2026.08 (Material 3) | 実装済み |
| Google Play 開発者サービス不使用 | 依存は AndroidX のみ。生体認証は **プラットフォーム標準 `android.hardware.biometrics.BiometricPrompt`**、FIDO 処理は自前実装 (`fido-core`) | 実装済み |
| アプリ起動中のみ認証 | Activity の onStart〜onStop の間 (= 画面表示中) だけ受付。前面から外れると即時に受付解除。HCE の優先サービス設定も onResume〜onPause のみ | 実装済み |
| 認証前に本人確認必須 | 「本人確認して開始」→ BiometricPrompt (Class 3 生体認証 / 設定により画面ロック) 成功後、設定秒数だけ受付。既定は 1 回の登録/認証で受付終了 | 実装済み |
| UI は TCSameuraDamMonitor ベース | テーマ、ドロワー (840dp 以上で常設サイドバー)、設定項目部品、マウスドラッグスクロール、自動縮小テキストを流用 | 実装済み |

> 「当該 Android 起動中のみ」は「本アプリが起動して画面に表示されている間のみ」と解釈した。

## 2. 全体構成

```
┌───────────────── Android 端末 (TCAndroidKey) ─────────────────┐
│  MainActivity (Compose UI)                                     │
│   ├ onStart/onStop ─→ AuthSessionManager.setForeground()       │
│   ├ BiometricPrompt ─→ AuthSessionManager.arm()                │
│   └ CardEmulation.setPreferredService (onResume/onPause)       │
│                                                                │
│  FidoHostApduService (HCE) ──┐      BluetoothHidAuthenticator  │
│   NfcCtapProcessor (APDU)    │       CtapHidProcessor (HID)    │
│                              ▼                ▼                │
│                 Ctap2Authenticator (CTAP2 コマンド処理)         │
│                    │                    │                      │
│     AuthorizationPolicy            CredentialStore             │
│   (AuthSessionManager)        (KeystoreCredentialStore)        │
│                                    │            │              │
│                         AndroidKeyStore    MetadataStore       │
│                        (EC P-256 秘密鍵)  (AES-GCM 暗号化 JSON) │
└────────────────────────────────────────────────────────────────┘
        ▲ NFC (ISO 14443-4 / ISO 7816-4)       ▲ Bluetooth HID
  PC/SC リーダー (RC-S300) / Android NFC     PC (ペアリング)
```

### 2.1 モジュール

| モジュール | 内容 | Android 依存 |
|---|---|---|
| `fido-core` | CBOR、CTAP2 認証器、NFC APDU 処理、CTAPHID フレーミング | なし (純 Kotlin/JVM。SDK なしでビルド・単体テスト可) |
| `app` | Keystore 実装、セッション/本人確認、HCE サービス、Bluetooth HID、Compose UI | あり |

プロトコル処理を Android から分離したことで、クラウド (SDK 不要) でもロジックの単体テストができ、
JCA ソフトウェア鍵で WebAuthn クライアント相当の署名検証まで行っている (`fido-core/src/test`)。

### 2.2 主要クラス

| クラス | 役割 |
|---|---|
| `fido.cbor.Cbor` | CTAP2 canonical CBOR のエンコード/デコード |
| `fido.ctap2.Ctap2Authenticator` | GetInfo / MakeCredential / GetAssertion / GetNextAssertion / Reset / Selection |
| `fido.ctap2.CredentialStore` | 鍵生成・署名・列挙・削除の抽象 |
| `fido.ctap2.AuthorizationPolicy` | UP/UV 判定の抽象 (前面表示・本人確認状態) |
| `fido.nfc.NfcCtapProcessor` | SELECT、NFCCTAP_MSG、コマンド/レスポンスチェイニング、拡張長 APDU |
| `fido.hid.CtapHidProcessor` | CTAPHID (INIT/PING/CBOR/CANCEL/KEEPALIVE/WINK/ERROR) |
| `keystore.KeystoreCredentialStore` | AndroidKeyStore 実装 |
| `auth.AuthSessionManager` | 前面表示状態・本人確認の受付期限・ワンタイム消費 |
| `auth.UserVerifier` | BiometricPrompt ラッパー |
| `nfc.FidoHostApduService` | HostApduService |
| `bluetooth.BluetoothHidAuthenticator` | BluetoothHidDevice 登録・レポート送受信 |

## 3. プロトコル仕様

### 3.1 CTAP2 (authenticatorGetInfo)

| キー | 値 |
|---|---|
| versions | `["FIDO_2_0"]` |
| aaguid | `523283ca-3c2c-48b5-8bff-a722f900e190` (本アプリ固有) |
| options | `rk: true, up: true, uv: true, plat: false` (clientPin は非対応 = 内蔵 UV のみ) |
| maxMsgSize | 2048 |
| transports | NFC: `["nfc"]` / Bluetooth HID: `["usb"]` (OS からは HID デバイスに見えるため) |
| algorithms | ES256 (-7) のみ |

- **clientPIN は実装しない**。ユーザー検証は端末内蔵の UV (生体認証 / 画面ロック) で行い、
  `uv` オプションが要求されたら UV フラグを立てて応答する。
  長さ 0 の pinAuth (プラットフォームのタッチ待ちプローブ) には `CTAP2_ERR_PIN_NOT_SET` を返す。
- **アテステーション**: 既定は `none`。設定で `packed` 自己アテステーション (クレデンシャル鍵で署名) を選べる。
- **署名カウンタ**: クレデンシャル毎に単調増加 (メタデータに保存)。
- **Discoverable credential (パスキー)**: `rk: true` で保存。同一 RP・同一ユーザー ID の再登録は上書き。
  allowList なしの GetAssertion で列挙し、複数ある場合は `numberOfCredentials` + GetNextAssertion。
- **非 discoverable credential**: credential ID はランダム 32 バイトで、鍵は常に端末内に保存 (鍵ラップはしない。
  Keystore の鍵は外部に出せないため)。
- 拡張 (hmac-secret, credProtect 等) は未対応 (無視する)。

### 3.2 NFC (CTAP 2.1 §11.3)

| APDU | 処理 |
|---|---|
| `00 A4 04 00 08 A0000006472F0001` | 受付中なら `"FIDO_2_0" 9000`、それ以外は `6A82` (FIDO アプレットが無いように見せる) |
| `80 10 00 00 Lc <CTAP2>` | CTAP2 リクエスト。`90 10 …` はコマンドチェイニング |
| `00 C0 00 00 Le` | GET RESPONSE (レスポンスチェイニング `61XX` の続き) |
| その他 (U2F 等) | `6D00` / `6E00` |

- 短い APDU は 256 バイト、拡張長 APDU は 1024 バイトずつチェイニングして応答する
  (NFC コントローラによる長フレームの不具合を避けるため)。
- CTAP 処理 (StrongBox 署名は数百 ms かかることがある) はワーカースレッドで行い、`sendResponseApdu` で応答する。
- `apduservice.xml`: `requireDeviceUnlock=true`, `requireDeviceScreenOn=true`, category `other`。

### 3.3 Bluetooth HID (実験的)

- `BluetoothHidDevice.registerApp()` で FIDO HID レポートディスクリプタ (64 バイト入出力、レポート ID なし) を登録。
- PC 側から本端末を Bluetooth デバイスとしてペアリングすると、FIDO HID デバイスとして見える。
- NFC と異なり通信中に待てるため、未確認ならその場で BiometricPrompt を表示し、
  `KEEPALIVE (UPNEEDED)` を 100 ms 間隔で送りながら最大 30 秒待つ。`CTAPHID_CANCEL` で中断。
- 制約: ホスト OS / ブラウザが「Bluetooth 接続の HID FIDO デバイス」を扱うかは環境依存。
  また Android 端末側の Bluetooth スタックの HID Device プロファイル対応状況にも依存する。

## 4. セキュリティ設計

### 4.1 認証受付の条件 (AND)

1. **アプリが前面表示中** (onStart〜onStop)。バックグラウンド・画面オフ・ロック中は受け付けない
   (HCE 側でも `requireDeviceUnlock` / `requireDeviceScreenOn`)。
2. **本人確認済みで受付期限内** (既定 60 秒、15〜300 秒で設定可)。
3. **ワンタイム** (既定 ON): 1 回の登録/認証 (UP を伴う操作) が成功した時点で受付を解除。
4. 受付外に NFC リーダーを検出した場合は SELECT を拒否し、本人確認ダイアログを表示する
   (確認後にもう一度かざす)。

### 4.2 Keystore 鍵の属性

| 属性 | 値 | 目的 |
|---|---|---|
| アルゴリズム | EC P-256 / SHA-256 (`PURPOSE_SIGN`) | ES256 |
| `setUserAuthenticationRequired(true)` | | 鍵使用にユーザー認証が必要 |
| `setUserAuthenticationParameters(300, BIOMETRIC_STRONG \| DEVICE_CREDENTIAL)` | 認証後 300 秒以内のみ署名可 | アプリ側の受付期限 (≤300 秒) の多重防御 |
| `setUnlockedDeviceRequired(true)` | | 端末ロック中は使用不可 |
| `setIsStrongBoxBacked(true)` | StrongBox 搭載時 (設定で変更可) | セキュアエレメントで保護。非搭載時は TEE |

- BiometricPrompt (CryptoObject なし) の成功でも Keystore に認証トークンが渡るため、時間制限付き鍵が使用可能になる。
  ※ 端末のロック解除も同じトークンを発行するため、**アプリ側の受付状態 (4.1) が主たる制御**であり、Keystore 側の制限は多重防御。
- 画面ロックを解除・変更すると鍵が無効化される場合がある (`KeyPermanentlyInvalidatedException`)。その鍵は使えなくなる。
- メタデータ (RP ID、ユーザー名、署名カウンタ、公開鍵) は Keystore の AES-256-GCM 鍵で暗号化してアプリ専用領域に保存。
- `allowBackup=false` + data extraction rules で全データをバックアップ・端末移行の対象外にする。
- **アプリをアンインストールすると全鍵が消える** (Keystore の仕様)。

### 4.3 その他

- 画面は `FLAG_SECURE` (スクリーンショット・画面共有不可)。
- イベントログはメモリ内のみ (永続化しない)。
- クレデンシャル削除、ワンタイム無効化、生体認証のみ無効化、PC からのリセット許可は本人確認が必要。

## 5. 画面構成 (TCSameuraDamMonitor ベース)

| 画面 | 内容 |
|---|---|
| セキュリティキー (メイン) | 受付状態カード (残り秒数・プログレス、「本人確認して開始」/「停止」)、接続方式 (NFC / Bluetooth / USB)、鍵の保管 (StrongBox/TEE・件数)、最近のイベント |
| クレデンシャル | RP・ユーザー・作成日時・最終使用・署名回数・パスキー/非検出・保管レベル。個別削除・全削除 |
| イベントログ | CTAP コマンドと結果、NFC/Bluetooth の接続イベント |
| 設定 | テーマ、認証受付時間、ワンタイム、生体認証のみ、かざし時の確認表示、StrongBox 優先、アテステーション、PC からのリセット許可、Bluetooth (実験的) |
| このアプリについて | バージョン、AAGUID、対応プロトコル、セキュリティ説明、ライセンス |

流用した UI 部品: `TCAndroidKeyTheme` (Material 3 / ダイナミックカラー)、ドロワー構成 (`ModalNavigationDrawer` ⇔ 840dp 以上で `PermanentDrawerSheet` + 開閉)、
`SettingsCategoryTitle` / `ThemeSettingItem` / `SettingItemSwitch` / `SettingItemReadOnly` / `SettingItemClickable` / `SettingsHelpText`、
`Modifier.mouseDragScroll`、`AutoResizingSingleLineText`、エッジツーエッジ設定。

## 6. 既知の制約・今後の課題

- **CTAP 2.1 / clientPIN 未対応**: 一部の RP やプラットフォームが「PIN 設定済み」を要求する場合に登録できない可能性がある。
  必要に応じて PIN プロトコル 2 と credentialManagement を追加する。
- **U2F (CTAP1) 未対応**: FIDO U2F のみ対応の古いサイトでは使えない。
- **NFC で未確認のままかざした場合は 2 度かざす必要がある** (SELECT 拒否 → 確認 → 再タップ)。
  CTAP 2.1 の NFCCTAP_GETRESPONSE (0x9100 ステータス) による待機はプラットフォーム対応がまちまちなため採用していない。
- **macOS のブラウザ + PC/SC リーダー**: macOS の Chrome は NFC (PC/SC) セキュリティキーに対応していない。
  Safari は USB スマートカードリーダー経由の NFC セキュリティキーに対応している可能性があるが未確認。
  macOS では `scripts/test/fido2_nfc_test.py` (python-fido2) による CTAP レベルの確認を基本とする。
- Bluetooth HID は実験的 (端末・OS 依存)。
