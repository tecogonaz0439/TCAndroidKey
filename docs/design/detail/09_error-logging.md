# DD-09 エラー処理・ログ

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-DD-09 |
| 版数 | 1.1 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.1 (2026-11-02): 外部レビュー対応 (例外の扱い、取消・失効・予約中のエラー、メタデータを読めない場合、logcat の出力内容)。`review/FIX_PLAN.md` |
| 関連要件 | FR-17, SEC-08, SEC-10 |

## 1. エラー処理の方針

- 外部入力 (APDU / CTAPHID / CBOR) の異常はプロトコルのエラー (SW / CTAPHID ERROR / CTAP ステータス) として返し、アプリを異常終了させない。
- Kotlin では検査例外 (`IOException`・`KeyStoreException` 等) も宣言なしに伝搬するため、`Ctap2Authenticator.process` と
  CTAPHID のワーカーは `Exception` をすべて捕捉してエラー応答に変換する (ワーカースレッドの未捕捉例外はアプリを終了させる)。
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
| Bluetooth でホストがキャンセル (処理開始前を含む) | 認可 | `0x2D` | ERROR "… KEEPALIVE_CANCEL" | — |
| 他のトランスポートの操作がワンタイムを予約中 | 認可 | `0x27` (NFC) / 待機 (Bluetooth) | WARNING "rejected: another operation is using the one-time authorization" | 先の操作の完了を待つ |
| 処理中に受付を停止・前面離脱 | 認可 (Lease) | `0x27` (登録は作成した鍵を削除) | ERROR "… (authorization revoked)" | — |
| 処理中に NFC が切断 | NFC | 応答を送らない | WARNING NFC "response discarded: reader disconnected during processing" | 再度かざす |
| GetNextAssertion の継続が無効 (停止後・別チャネル・切断後) | CTAP | `0x30` | ERROR "… NOT_ALLOWED (<理由>)" | GetAssertion からやり直す |
| メタデータを読み込めない | 鍵管理 | `0x7F` (登録・認証を拒否) | ERROR Keystore "failed to load credentials: …"、SC-02 に案内を表示 | SC-02 で「初期化 (すべて削除)」(DD-07 §5.1) |
| メタデータの保存失敗 | 鍵管理 | `0x7F` | ERROR "… (failed to save credential metadata: …)" | 空き容量を確認 |
| 想定外の例外 | CTAP / CTAPHID | `0x7F` | ERROR "… (<例外>)" | — |

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
| Session | WARNING | `rejected: another operation is using the one-time authorization` |
| NFC | WARNING | `response discarded: reader disconnected during processing` |
| Bluetooth | INFO | `registered as FIDO HID device; waiting for host` / `HID device registration ended; …` / `host connected: <名前>` / `host disconnected` / `waiting for user verification (<RP>)` |
| Bluetooth | ERROR | `failed to register HID device` / `sendReport denied: …` |
| Keystore | INFO | `deleted credential for <RP>` / `deleted all credentials` |
| Keystore | ERROR | `failed to load credentials: …` / `failed to delete credential(s): …` |

### 3.3 取り扱い

- メモリ内のみ・最大 300 件。プロセス終了または [消去] で消える (SEC-08)。
- RP ID・ユーザー名を含むため、ログを共有する場合はテスト用アカウントであることを確認する。
- 署名・鍵・clientDataHash などの値は記録しない。
- logcat (タグ `TCAndroidKey`) にも出力するが、**RP ID・ユーザー名・Bluetooth ホスト名を含めない**
  (例: `authenticatorMakeCredential → CTAP2_OK`)。logcat は ADB・バグレポート・ログ閲覧権限を持つアプリから読めるため。
  RP ID・ユーザー名はアプリ内のログ画面 (SC-03) でのみ確認できる。
- 実機試験時は `adb logcat -s TCAndroidKey` でコマンドと結果の流れを取得し、RP・ユーザーは SC-03 で確認する。
