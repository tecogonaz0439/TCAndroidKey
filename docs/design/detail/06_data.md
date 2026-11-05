# DD-06 データ設計

| 項目 | 内容 |
|---|---|
| 文書番号 | TCSKE-DD-06 |
| 版数 | 1.8 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.8 (2026-11-05): `label` 項目 (クレデンシャルのタイトル、FR-27) を追加。§3.1 の読み込み失敗の記述を §3.3 (読めない場合は UNAVAILABLE) に合わせて訂正 |
| 改訂 | 1.7 (2026-11-05): コードレビュー (2026-11-05) の指摘への対応 (重複の整理)。暗号化ファイルの処理を `KeystoreEncryptedFile` に共通化 (形式は変更なし) |
| 改訂 | 1.6 (2026-11-05): コードレビュー (2026-11-05) の指摘への対応 (作成日時の単調性) |
| 改訂 | 1.5 (2026-11-05): clientPIN の保存 (`pin.bin`、§3.4) を追加。§5 に `fido_hmac_`・PIN の暗号鍵を追加し、全削除でメタデータ暗号鍵も削除する記述に訂正 |
| 改訂 | 1.4 (2026-11-05): `credProtect` 項目を追加。credentialManagement によるユーザー情報の更新を追記 |
| 改訂 | 1.3 (2026-11-05): hmac-secret の HMAC 鍵と `hmacSecret` 項目を追加 |
| 改訂 | 1.2 (2026-11-02): 設定 `notice_acknowledged` を追加、言語の保存先を明記 |
| 改訂 | 1.1 (2026-11-02): 外部レビュー対応 (等価性・順序、読み込み失敗の扱い、logcat 出力、巻き戻しの非検出)。`review/FIX_PLAN.md` |
| 実装 | `fido-core/.../ctap2/CredentialStore.kt`, `app/.../keystore/MetadataStore.kt`, `data/SettingsRepository.kt`, `data/EventLogRepository.kt` |
| 関連要件 | FR-07, FR-17, FR-18, SEC-05, SEC-06, SEC-08 |

## 1. データ一覧

| データ | 保存先 | 形式 | 永続 | バックアップ |
|---|---|---|---|---|
| 秘密鍵 (クレデンシャル毎) | Android Keystore | EC P-256 鍵エントリ | ○ | 対象外 |
| hmac-secret の HMAC 鍵 (hmac-secret 付きのクレデンシャル毎) | Android Keystore | HMAC-SHA256 鍵エントリ | ○ | 対象外 |
| メタデータ暗号鍵 | Android Keystore | AES-256 鍵エントリ | ○ | 対象外 |
| PIN の暗号鍵 | Android Keystore | AES-256 鍵エントリ (`tcsecuritykeyemulator_pin_v1`) | ○ | 対象外 |
| PIN (ハッシュと試行回数) | `filesDir/pin.bin` | AES-GCM 暗号化 JSON (§3.4) | ○ | 対象外 |
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
| `createdAtMillis` | Long | 作成日時 (エポックミリ秒)。既存のどの credential より大きくする (`nextCreatedAt`。時計が巻き戻っても上書き登録・discoverable の順序が崩れない) |
| `lastUsedAtMillis` | Long? | 最終署名日時 |
| `signCount` | Long | 署名カウンタ (作成時 0、署名毎 +1) |
| `publicKeyX` / `publicKeyY` | ByteArray (32) | 公開鍵座標 |
| `securityLevel` | KeySecurityLevel | 鍵生成時の Keystore セキュリティレベル |
| `hmacSecret` | Boolean | hmac-secret 拡張付きで登録されたか (HMAC 鍵がある)。既定 false |
| `credProtect` | Int | credProtect の保護レベル (1〜3。DD-01 §12.3)。既定 1 |
| `label` | String? | 利用者が付けたタイトル (FR-27)。null は未設定。保存時に `normalizeLabel` で前後の空白・制御文字を除き、64 コードポイントまでにする (空は null)。アプリ内の表示専用で、CTAP の応答 (credentialManagement の列挙を含む) には使わない |

- non-discoverable credential も鍵は端末内に保存する (credential ID に鍵をラップしない。Keystore の鍵は外部に出せないため)。
- 同一 RP・同一ユーザー ID の discoverable credential は 1 件のみ (再登録で置き換え。旧 credential は新しい登録の完成後に削除する)。
- 等価性 (`equals`) は全フィールドの内容で判定する (署名カウンタ・最終使用日時の更新が StateFlow で UI に通知されるようにするため)。
  同じ credential かどうかは `isSameCredential` (ID の比較) で判定する。
- 表示するタイトル `title` は `label`、なければ `defaultTitle` (rp.name が空でなければ rp.name、なければ RP ID)。
  上書き登録では旧 credential の `label` を引き継ぐ (DD-01 §3.2 手順 9)。credentialManagement の updateUserInformation では変わらない。
- discoverable credential の順序は作成日時の新しい順 (`NEWEST_FIRST`、同時刻は ID 順)。最終使用日時は順序に影響しない。

## 3. 暗号化メタデータファイル

### 3.1 ファイル形式

| オフセット | 長さ | 内容 |
|---|---|---|
| 0 | 12 | GCM IV (Keystore が生成) |
| 12 | 可変 | AES-256-GCM 暗号文 ‖ 認証タグ (128 bit) |

- 読み書きは `KeystoreEncryptedFile` (PIN ファイル §3.4 と共通。エイリアスとファイル名だけが異なる)。
- 暗号鍵: Keystore エイリアス `tcsecuritykeyemulator_metadata_v1`、`PURPOSE_ENCRYPT | PURPOSE_DECRYPT`、GCM / NoPadding、ユーザー認証不要 (一覧表示のため)。
- 書き込みは `AtomicFile` による原子的な置き換え。変更 (作成・削除・カウンタ更新・ユーザー情報の更新・タイトルの編集) の都度、全件を書き直す。
- ファイルがない場合は 0 件として扱う。ファイルがあるのに読めない場合は 0 件として扱わず、UNAVAILABLE にする (§3.3)。

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
    "securityLevel": "STRONGBOX",
    "hmacSecret": true,
    "credProtect": 2,
    "label": "Alice (work)"
  }
]
```

省略可能な項目 (`rpName`, `userName`, `userDisplayName`, `lastUsedAt`) は null の場合キー自体を出力しない。
`hmacSecret` は true の場合のみ、`credProtect` は 1 以外の場合のみ、`label` は設定した場合のみ出力し、ない場合は既定値 (false / 1 / 未設定) として読む
(これらの項目を追加する前のファイルもそのまま読める)。
`user.name`・`user.displayName` は credentialManagement の updateUserInformation で置き換わる (DD-01 §12.4)。`label` は SC-02 のタイトルの編集 (`CredentialStore.updateLabel`、DD-08 §3) で置き換わる。

### 3.3 整合性

アプリ起動後の初回アクセス時 (`KeystoreCredentialStore.load()`) に、Keystore に鍵エイリアスが存在しないメタデータを除去し、
除去があればファイルを書き直す。

| 状態 | 扱い |
|---|---|
| ファイルがない | 空のストアとして扱う |
| ファイルがあるが読めない (12 バイト以下、GCM タグ不一致、暗号鍵がない、JSON 不正) | **空として扱わない**。ストアを UNAVAILABLE にし、上書きを伴う操作を拒否する (DD-07 §5) |

- AES-GCM により暗号文の改ざん・破損は検出する。ただし、以前に保存した**正当なファイルへの巻き戻し** (署名カウンタを古い値へ戻す等)
  は検出しない。同じファイル内に世代番号を持たせても、ファイル全体を戻されれば検出できないため、本アプリでは対策しない
  (アプリ専用領域のファイルを書き換えられる攻撃者を想定外とする。BD-05 T-04)。
- 更新は新しいスナップショットを作って保存し、保存に成功してからキャッシュ・UI へ反映する (保存失敗時にメモリとファイルが食い違わない)。


### 3.4 PIN ファイル (`pin.bin`)

形式は §3.1 と同じ (GCM IV 12 バイト ‖ 暗号文 ‖ タグ)。暗号鍵は Keystore エイリアス `tcsecuritykeyemulator_pin_v1` (ユーザー認証不要)。

```json
{"hash": "<LEFT(SHA-256(PIN), 16) の hex 32 文字>", "retries": 8}
```

| 状態 | 扱い |
|---|---|
| ファイルがない | PIN 未設定 |
| 読める | PIN 設定済み。`hash` が 16 バイト、`retries` が 0〜8 でなければ読めないものとして扱う |
| ファイルがあるが読めない (暗号鍵がない、GCM タグ不一致、JSON 不正) | 空として扱わない。UNAVAILABLE とし、PIN の操作を拒否する (DD-01 §13.1)。アプリの「PIN を消去」でファイルと暗号鍵を削除して初期化する |

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
| `notice_acknowledged` | Boolean | false | | 初回起動時の注意書き (DL-03) を確認済み |

表示言語はアプリの設定ファイルには保存せず、OS のアプリ別言語設定 (`LocaleManager`) に保存される (DD-08 §5.1)。

範囲外・不明な値は既定値として読み込む。

## 5. Keystore エイリアス

| エイリアス | 種別 | 用途 |
|---|---|---|
| `fido_cred_<credentialId の hex>` | EC P-256 (署名) | クレデンシャル秘密鍵 |
| `fido_hmac_<credentialId の hex>` | HMAC-SHA256 (署名) | hmac-secret の CredRandom の導出 (DD-07 §6) |
| `tcsecuritykeyemulator_metadata_v1` | AES-256 (暗号化) | メタデータ暗号鍵 |
| `tcsecuritykeyemulator_pin_v1` | AES-256 (暗号化) | PIN の暗号鍵 (§3.4) |

いずれも変更しない識別子 (変えると既存の端末の鍵・データを使えなくなる)。
全削除は `fido_cred_`・`fido_hmac_` で始まるエイリアスをすべて削除し、メタデータ暗号鍵とメタデータファイルも削除する
(次回の保存で作り直す。DD-07 §5)。PIN の暗号鍵と PIN ファイルも削除する (DD-07 §7)。

## 6. イベントログ (LogEntry)

| 項目 | 内容 |
|---|---|
| `id` | 連番 |
| `timestampMillis` | 記録日時 |
| `level` | `INFO` / `SUCCESS` / `WARNING` / `ERROR` |
| `source` | `NFC` / `Bluetooth` / `Session` / `Keystore` |
| `message` | 内容 (DD-09 §3) |

最大 300 件 (新しい順)。logcat (タグ `TCSecurityKeyEmulator`) にも出力するが、logcat には RP ID・ユーザー名を含めない (DD-09 §3.3)。

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
