# DD-06 データ設計

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-DD-06 |
| 版数 | 1.0 |
| 作成日 | 2026-11-02 |
| 実装 | `fido-core/.../ctap2/CredentialStore.kt`, `app/.../keystore/MetadataStore.kt`, `data/SettingsRepository.kt`, `data/EventLogRepository.kt` |
| 関連要件 | FR-07, FR-17, FR-18, SEC-05, SEC-06, SEC-08 |

## 1. データ一覧

| データ | 保存先 | 形式 | 永続 | バックアップ |
|---|---|---|---|---|
| 秘密鍵 (クレデンシャル毎) | Android Keystore | EC P-256 鍵エントリ | ○ | 対象外 |
| メタデータ暗号鍵 | Android Keystore | AES-256 鍵エントリ | ○ | 対象外 |
| クレデンシャルのメタデータ | `filesDir/credentials.bin` | AES-GCM 暗号化 JSON | ○ | 対象外 |
| 設定 | SharedPreferences `settings` | キー・値 | ○ | 対象外 |
| イベントログ | メモリ | リスト (最大 300 件) | × | — |
| 認証受付セッション | メモリ | `AuthSessionState` | × | — |

バックアップ除外: `android:allowBackup="false"`、`@xml/data_extraction_rules` で cloud-backup / device-transfer の
root / file / database / sharedpref / external をすべて除外。

## 2. クレデンシャル (StoredCredential)

| 項目 | 型 | 内容 |
|---|---|---|
| `id` | ByteArray (32) | クレデンシャル ID。`SecureRandom` で生成 |
| `rpId` | String | RP ID (例: `webauthn.io`) |
| `rpName` | String? | RP 名 |
| `user.id` | ByteArray (1〜64) | ユーザーハンドル |
| `user.name` | String? | ユーザー名 |
| `user.displayName` | String? | 表示名 |
| `discoverable` | Boolean | `rk: true` で登録されたか (パスキー) |
| `createdAtMillis` | Long | 作成日時 (エポックミリ秒) |
| `lastUsedAtMillis` | Long? | 最終署名日時 |
| `signCount` | Long | 署名カウンタ (作成時 0、署名毎 +1) |
| `publicKeyX` / `publicKeyY` | ByteArray (32) | 公開鍵座標 |
| `securityLevel` | KeySecurityLevel | 鍵生成時の Keystore セキュリティレベル |

- non-discoverable credential も鍵は端末内に保存する (credential ID に鍵をラップしない。Keystore の鍵は外部に出せないため)。
- 同一 RP・同一ユーザー ID の discoverable credential は 1 件のみ (再登録で置き換え)。

## 3. 暗号化メタデータファイル

### 3.1 ファイル形式

| オフセット | 長さ | 内容 |
|---|---|---|
| 0 | 12 | GCM IV (Keystore が生成) |
| 12 | 可変 | AES-256-GCM 暗号文 ‖ 認証タグ (128 bit) |

- 暗号鍵: Keystore エイリアス `tcandroidkey_metadata_v1`、`PURPOSE_ENCRYPT | PURPOSE_DECRYPT`、GCM / NoPadding、ユーザー認証不要 (一覧表示のため)。
- 書き込みは `AtomicFile` による原子的な置き換え。変更 (作成・削除・カウンタ更新) の都度、全件を書き直す。
- 読み込み失敗 (ファイルなし・復号失敗) は 0 件として扱う。

### 3.2 平文 JSON

```json
[
  {
    "id": "<hex 64 文字>",
    "rpId": "webauthn.io",
    "rpName": "webauthn.io",
    "userId": "<hex>",
    "userName": "alice",
    "userDisplayName": "Alice",
    "discoverable": true,
    "createdAt": 1793606400000,
    "lastUsedAt": 1793606460000,
    "signCount": 3,
    "x": "<hex 64 文字>",
    "y": "<hex 64 文字>",
    "securityLevel": "STRONGBOX"
  }
]
```

省略可能な項目 (`rpName`, `userName`, `userDisplayName`, `lastUsedAt`) は null の場合キー自体を出力しない。

### 3.3 整合性

アプリ起動後の初回アクセス時 (`KeystoreCredentialStore.load()`) に、Keystore に鍵エイリアスが存在しないメタデータを除去し、
除去があればファイルを書き直す。

## 4. 設定 (SharedPreferences `settings`)

| キー | 型 | 既定値 | 値の範囲 | 内容 |
|---|---|---|---|---|
| `theme` | String | `SYSTEM` | `SYSTEM` / `LIGHT` / `DARK` | テーマ |
| `auth_window_seconds` | Int | 60 | 15 / 30 / 60 / 120 / 300 | 認証受付時間 |
| `one_time_authorization` | Boolean | true | | 本人確認 1 回につき認証 1 回 |
| `biometric_only` | Boolean | false | | 本人確認を生体認証のみに限定 |
| `prompt_on_tap` | Boolean | true | | 確認前にかざしたら確認画面を表示 |
| `attestation_mode` | String | `NONE` | `NONE` / `SELF` | アテステーション |
| `allow_reset_from_client` | Boolean | false | | OS からのリセットを許可 |
| `prefer_strongbox` | Boolean | true | | 新規鍵を StrongBox に生成 (非搭載時は無効) |
| `bluetooth_enabled` | Boolean | false | | Bluetooth HID (実験的) |

範囲外・不明な値は既定値として読み込む。

## 5. Keystore エイリアス

| エイリアス | 種別 | 用途 |
|---|---|---|
| `fido_cred_<credentialId の hex>` | EC P-256 (署名) | クレデンシャル秘密鍵 |
| `tcandroidkey_metadata_v1` | AES-256 (暗号化) | メタデータ暗号鍵 |

全削除は `fido_cred_` で始まるエイリアスをすべて削除する (メタデータ暗号鍵は残す)。

## 6. イベントログ (LogEntry)

| 項目 | 内容 |
|---|---|
| `id` | 連番 |
| `timestampMillis` | 記録日時 |
| `level` | `INFO` / `SUCCESS` / `WARNING` / `ERROR` |
| `source` | `NFC` / `Bluetooth` / `Session` / `Keystore` |
| `message` | 内容 (DD-09 §3) |

最大 300 件 (新しい順)。同じ内容を logcat (タグ `TCAndroidKey`) にも出力する。

## 7. 定数

| 定数 | 値 |
|---|---|
| AAGUID | `523283ca-3c2c-48b5-8bff-a722f900e190` |
| クレデンシャル ID 長 | 32 バイト |
| Keystore 認証有効期間 | 300 秒 |
| GetNextAssertion の有効時間 | 30 秒 |
| Bluetooth 本人確認待ち | 最大 30 秒、keepalive 100 ms 間隔 |
| NFC コマンドチェイン上限 | 8192 バイト |
| CTAP maxMsgSize | 2048 バイト |
