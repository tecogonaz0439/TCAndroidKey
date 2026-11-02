# DD-09 エラー処理・ログ

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-DD-09 |
| 版数 | 1.0 |
| 作成日 | 2026-11-02 |
| 関連要件 | FR-17, SEC-08, SEC-10 |

## 1. エラー処理の方針

- 外部入力 (APDU / CTAPHID / CBOR) の異常はプロトコルのエラー (SW / CTAPHID ERROR / CTAP ステータス) として返し、アプリを異常終了させない。
- 想定外の実行時例外は、CTAP 層で `0x7F`、HCE 層で `6F00`、CTAPHID 層で CBOR 応答 `0x7F` に変換する。
- 利用者の操作に関するエラーはスナックバーで通知する (DD-08 §7)。
- 処理結果はすべてイベントログに記録する。

## 2. エラー対応表

| 事象 | 層 | クライアントへの応答 | イベントログ | 利用者の対処 |
|---|---|---|---|---|
| アプリが前面表示されていない状態でかざした | NFC 選択ゲート | `6A82` | WARNING NFC "reader detected but the app is not in the foreground; rejected" | アプリを開く |
| 本人確認前にかざした | NFC 選択ゲート | `6A82` + 本人確認ダイアログ | WARNING NFC "reader detected before verification; asking for verification" | 本人確認後に再度かざす |
| SELECT 受理後に受付時間が切れた | 認可 | `0x27` | ERROR NFC "… → CTAP2_ERR_OPERATION_DENIED (user verification required)" | 再度本人確認 |
| 鍵の認証有効期間切れ・無効化 | 鍵管理 | `0x27` | ERROR "… (key use not authorized / user authentication expired / key permanently invalidated …)" | 再度本人確認。無効化の場合は削除して再登録 |
| 画面ロック未設定で登録 | 鍵管理 | `0x27` | ERROR "… (key generation failed: …)" | 画面ロックを設定 |
| 該当クレデンシャルなし | CTAP | `0x2E` | WARNING "authenticatorGetAssertion → CTAP2_ERR_NO_CREDENTIALS rp=…" | 登録状況を確認 |
| 重複登録 (excludeList) | CTAP | `0x19` | ERROR "… CREDENTIAL_EXCLUDED" | 既存のクレデンシャルを使う |
| ES256 非対応の要求 | CTAP | `0x26` | ERROR | RP の設定 (pubKeyCredParams) を確認 |
| PIN を要求するクライアント | CTAP | `0x35` / `0x33` | ERROR "… PIN_NOT_SET" 等 | RP の userVerification 設定・クライアントを確認 (AP-C) |
| リセット不許可 | CTAP | `0x27` | ERROR "… (reset disabled in settings)" | 必要なら設定で許可 |
| 不正な CBOR | CTAP | `0x12` / `0x11` / `0x14` | ERROR | (クライアントの不具合) |
| 不正な APDU | NFC | `6700` / `6D00` / `6E00` | なし | — |
| Bluetooth で本人確認待ちタイムアウト | 認可 | `0x2F` | INFO "waiting for user verification" → ERROR "… USER_ACTION_TIMEOUT" | 30 秒以内に本人確認 |
| Bluetooth でホストがキャンセル | 認可 | `0x2D` | ERROR "… KEEPALIVE_CANCEL" | — |
| メタデータの読み込み失敗 | 鍵管理 | — (0 件として動作) | ERROR Keystore "failed to load credentials: …" (画面起動時) | — |

## 3. イベントログの仕様

### 3.1 CTAP イベントの記録形式

```
<コマンド名> → <ステータス名>[ rp=<RP ID>][ user=<ユーザー名>][ (<詳細>)]
```

例: `authenticatorMakeCredential → CTAP2_OK rp=webauthn.io user=alice`

| 条件 | レベル |
|---|---|
| 成功 (GetInfo 以外) | SUCCESS |
| 成功 (GetInfo) | INFO |
| `NO_CREDENTIALS` | WARNING |
| その他のエラー | ERROR (詳細を付記) |

### 3.2 その他のイベント

| source | レベル | メッセージ |
|---|---|---|
| Session | INFO | `verified: accepting authentication for <N>s` / `authorization ended: <stopped by user / one-time authorization used>` |
| NFC | INFO | `reader disconnected (link loss / deselected)` |
| NFC | WARNING | 選択ゲートでの拒否 (§2) |
| NFC | ERROR | `APDU processing failed: <例外>` |
| Bluetooth | INFO | `registered as FIDO HID device; waiting for host` / `host connected: <名前>` / `host disconnected` / `waiting for user verification (<RP>)` |
| Bluetooth | ERROR | `failed to register HID device` / `sendReport denied: …` |
| Keystore | INFO | `deleted credential for <RP>` / `deleted all credentials` |

### 3.3 取り扱い

- メモリ内のみ・最大 300 件。プロセス終了または [消去] で消える (SEC-08)。
- RP ID・ユーザー名を含むため、ログを共有する場合はテスト用アカウントであることを確認する。
- 署名・鍵・clientDataHash などの値は記録しない。
- logcat (タグ `TCAndroidKey`) にも同じ内容を出力する。実機試験時は `adb logcat -s TCAndroidKey` で取得する。
