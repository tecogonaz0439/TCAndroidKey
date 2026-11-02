# 外部レビュー (ecd6e49) 指摘の精査結果と修正プラン

ChatGPT Pro によるレビュー (対象コミット `ecd6e49`、29 件) を、コードと照合して精査した結果と修正計画。
重大度は本アプリの前提 (テスト用ツール・テスト用アカウントのみ、PRE-01〜05) で再評価した。

## 方針の決定事項

| 項目 | 決定 |
|---|---|
| S-07 署名鍵 | 公開 debug 鍵を維持し、残存リスクを設計書に明記する (受容)。非公開鍵の選択は今後の任意課題 |
| O-02 読み込み失敗 | ストアを利用不可にし、初期化 (全削除) のみ許可する |
| ワンタイム OFF 時の同時要求 | 予約による排他はワンタイム ON 時のみ。OFF 時は NFC と Bluetooth の同時処理を許可する |

## 判定一覧

| ID | 判定 | 再評価 | 方針 | Phase |
|---|---|---|---|---|
| S-01 | 妥当 | High | 修正 (共有ゲートで判定と予約を原子化) | 1 ✅ |
| S-02 | 妥当 | High | 修正 (失効と消費の分離、継続操作に Lease を保持) | 1 ✅ |
| S-03 | 妥当 | Medium | 修正 (要求ごとの取消トークン) | 1 ✅ |
| S-04 | 妥当と推定 | Medium | 修正 (NFC 接続世代) | 1 ✅ |
| S-05 | 妥当 | Low | 修正 (認可後に NO_CREDENTIALS) | 1 ✅ |
| S-06 | 妥当 | Medium | 修正 (logcat から RP/ユーザー情報を除く) | 5 |
| S-07 | 事実は正しい | — | ドキュメント (残存リスク受容) | 6 |
| S-08 | 妥当 | Info | ドキュメント | 6 |
| F-01 | 妥当 | High | 修正 | 2 |
| F-02 | 妥当 | Low | 修正 (チェーン破棄のみ。P1/P2 厳格検証はしない) | 2 |
| F-03 | 妥当 (クライアント側) | — | ドキュメント (互換性表に版・API 層) | 6 |
| F-04 | 理論上 | Low | ドキュメント・実機確認 | 6 |
| F-05 | 妥当 | Medium | 修正 | 3 |
| F-06 | 妥当 | Low | 修正 | 3 |
| F-07 | 妥当 | Low | 一部修正 (MC の `up:true` 拒否は不採用) | 3 |
| F-08 | 妥当 | Low | 修正 | 3 |
| F-09 | 妥当 | Low | 修正 | 3 |
| F-10 | 妥当 | Medium | 修正 | 4 |
| F-11 | 妥当 (SHOULD) | Low | 一部修正 (キー順序検証は不採用) | 3 |
| F-12 | 妥当 (Kotlin では検査例外も素通りし、BT ワーカーでアプリ終了) | High | 修正 | 1 ✅ |
| F-13 | 妥当 | Medium | 修正 | 4 |
| F-14 | — | — | 不採用 (ホストは BT HID を USB HID として扱う。理由を設計書に記録) | 6 |
| O-01 | 妥当 | Medium | 修正 | 1 ✅ |
| O-02 | 妥当 | Medium | 修正 | 4 |
| O-03 | 妥当 | Low | 修正 | 4 |
| O-04 | 妥当 | Medium | 修正 | 5 |
| O-05 | 妥当 (流用元由来) | Low | 修正 | 5 |
| O-06 | 妥当 | Low | 修正 | 5 |
| O-07 | 妥当 | Low | 修正 | 5 |
| A-1 (追加) | PIN プローブで認可を完了通知しない | — | 修正 | 1 ✅ |
| A-2 (追加) | SOFTWARE 鍵の受入方針 | — | 警告表示 | 5 |

## Phase

1. 認可と操作寿命 — S-01〜S-05, O-01, F-12, A-1 ✅
2. NFC 互換性 — F-01, F-02
3. CTAP 境界条件 — F-05〜F-09, F-11
4. 永続化・Bluetooth 復帰 — F-10, O-02, O-03, F-13
5. ログ・試験スクリプト・UI — S-06, O-04〜O-07, A-2
6. 設計書 — S-07, S-08, F-03, F-04, F-14、Phase 1〜5 の設計反映

## Phase 1 の実装概要

- `fido-core/.../session/AuthorizationGate.kt` (新規): 前面・受付・予約・世代を 1 ロックで管理する共有ゲート。
  - 判定と予約を原子的に行う (ワンタイム ON 時は 1 操作のみ許可)。
  - 明示的な停止・前面離脱で epoch を進めて全 Lease を失効させる。ワンタイムの消費では失効させない。
  - 消費は許可時の arm に対してのみ有効 (古い操作の完了で新しい受付を終了させない)。
- `AuthorizationLease` (新規 API): `isValid()` / `complete(consumed)`。`AuthorizationPolicy.onOperationCompleted` は廃止。
- `KeepAlive.isCancelled` (新規 API): 要求ごとの取消トークン。
- `Ctap2Authenticator`
  - 鍵生成・署名の直前と応答の直前に Lease と取消を確認する。応答しない登録は削除する。
  - GetNextAssertion は元の Lease・取消トークン・チャネル (CID) が有効な場合のみ実行する。
  - 認可を経てから NO_CREDENTIALS を返す。すべての経路で Lease を complete する。
  - すべての例外を CTAP ステータスへ変換する。`resetSession()` はブロックしない。
- `CtapHidProcessor`: 操作単位のトークン。CANCEL は実行前でも失われない。割当済み CID への INIT / reset で操作を破棄し応答を送らない。BUSY は finally で解放。LOCK は未実装として ERR_INVALID_CMD。組立タイムアウトで ERR_MSG_TIMEOUT。
- `FidoHostApduService`: 接続世代を `onDeactivated` で即座に進め、古い世代の処理を取り消し応答を破棄する。
- `BluetoothHidAuthenticator.stop()`: 先に取消し、CTAP のロックを待たない。
- `AuthSessionManager`: `AuthorizationGate` を包む薄い層に変更。
- テスト: 39 → 75 件 (`AuthorizationGateTest`, `Ctap2AuthorizationTest`, CTAPHID の取消・再同期・例外)。
