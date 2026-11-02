# DD-03 Bluetooth HID トランスポート (実験的)

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-DD-03 |
| 版数 | 1.0 |
| 作成日 | 2026-11-02 |
| 実装 | `fido-core/.../hid/CtapHidProcessor.kt`, `app/.../bluetooth/BluetoothHidAuthenticator.kt` |
| 関連要件 | FR-02 |

> 本トランスポートは実験的機能であり、ホスト OS / ブラウザ・端末の Bluetooth スタックによっては動作しない。

## 1. HID デバイスの登録

### 1.1 SDP 設定

| 項目 | 値 |
|---|---|
| name / description / provider | `TCAndroidKey` / `FIDO2 security key` / `tecogonaz` |
| subclass | `SUBCLASS1_NONE` |
| QoS | 指定なし (null) |

### 1.2 レポートディスクリプタ

```
06 D0 F1   Usage Page (FIDO Alliance 0xF1D0)
09 01      Usage (CTAPHID)
A1 01      Collection (Application)
09 20        Usage (Input Report Data)
15 00        Logical Minimum (0)
26 FF 00     Logical Maximum (255)
75 08        Report Size (8)
95 40        Report Count (64)
81 02        Input (Data, Var, Abs)
09 21        Usage (Output Report Data)
15 00 26 FF 00 75 08 95 40
91 02        Output (Data, Var, Abs)
C0         End Collection
```

レポート ID は使用しない (入出力とも 64 バイト)。

### 1.3 権限

| 権限 | 用途 |
|---|---|
| `BLUETOOTH_CONNECT` (実行時) | HID Device プロファイルの登録・レポート送受信・ホスト名取得 |
| `BLUETOOTH_ADVERTISE` (実行時) | 検出可能化 (`ACTION_REQUEST_DISCOVERABLE`、120 秒) |

## 2. CTAPHID 仕様

### 2.1 パケット形式

| 種別 | 形式 | データ長 |
|---|---|---|
| 初期化パケット | CID (4) ‖ CMD (1, bit7=1) ‖ BCNTH ‖ BCNTL ‖ DATA | 最大 57 |
| 継続パケット | CID (4) ‖ SEQ (1, 0〜127) ‖ DATA | 最大 59 |

最大メッセージ長は 57 + 128 × 59 = 7609 バイト。

### 2.2 コマンド

| CMD | 名前 | 処理 |
|---|---|---|
| 0x86 | INIT | ブロードキャスト CID (`FFFFFFFF`) なら新しい CID を払い出す。既存 CID なら再同期。応答: nonce (8) ‖ CID (4) ‖ プロトコル 2 ‖ バージョン 1.0.0 ‖ capabilities `0x0D` (WINK・CBOR・NMSG) |
| 0x81 | PING | 受信データをそのまま返す |
| 0x90 | CBOR | CTAP2 要求をワーカーで処理し、応答を返す |
| 0x91 | CANCEL | 処理中の CID からなら本人確認待ちを中断 (`KEEPALIVE_CANCEL`) |
| 0x88 | WINK | 空の応答 |
| 0x84 | LOCK | 空の応答 (ロックはしない) |
| 0x83 | MSG (CTAP1) | `ERR_INVALID_CMD` (NMSG) |
| 0xBB | KEEPALIVE (送信のみ) | 処理中 1 = PROCESSING、2 = UPNEEDED |
| 0xBF | ERROR (送信のみ) | エラーコード 1 バイト |

### 2.3 エラー

| コード | 名前 | 発生条件 |
|---|---|---|
| 0x01 | INVALID_CMD | 未対応コマンド |
| 0x03 | INVALID_LEN | INIT の長さが 8 以外、7609 超、CBOR が空 |
| 0x04 | INVALID_SEQ | 継続パケットの SEQ 不一致 (組み立て中のメッセージを破棄) |
| 0x06 | CHANNEL_BUSY | CBOR 処理中、または別 CID のメッセージ組み立て中 |
| 0x0B | INVALID_CHANNEL | CID = 0、ブロードキャスト CID で INIT 以外、未払い出しの CID |

組み立て中のメッセージは、最後のパケットから 3 秒で破棄する。払い出し済み CID が 64 を超えたら一覧を初期化する。

## 3. 本人確認の待機

Bluetooth 用の `TransportPolicy` はブロッキング型とする (DD-05 §2.3)。

```mermaid
sequenceDiagram
    participant H as ホスト
    participant P as CtapHidProcessor
    participant W as fido-bt-ctap ワーカー
    participant S as AuthSessionManager
    participant UI as MainActivity
    H->>P: CBOR (GetAssertion)
    P->>W: 処理を投入 (busyCid 設定)
    W->>S: authorize (未確認)
    S->>UI: 本人確認を要求
    loop 100 ms 毎 (最大 30 秒)
        W-->>H: KEEPALIVE (UPNEEDED)
    end
    UI->>S: arm() (指紋認証成功)
    S-->>W: Granted
    W-->>H: CBOR 応答
```

| 事象 | 結果 |
|---|---|
| 受付状態になった | 処理を続行 |
| ホストから CANCEL | `0x2D KEEPALIVE_CANCEL` |
| アプリが前面から外れた | `0x27 OPERATION_DENIED` |
| 30 秒経過 | `0x2F USER_ACTION_TIMEOUT` |

## 4. BluetoothHidAuthenticator の処理

| 処理 | 内容 |
|---|---|
| `start()` | アダプタ・権限・Bluetooth オンを確認し、`getProfileProxy(HID_DEVICE)` → `registerApp(sdp, null, null, executor, callback)` |
| `stop()` | `unregisterApp()`、`closeProfileProxy()`、状態初期化 |
| `onConnectionStateChanged` | 接続: ホストを記録して CONNECTED。切断: CTAPHID・CTAP2 セッションを初期化して WAITING_FOR_HOST |
| `onInterruptData` / `onSetReport(OUTPUT)` | 出力レポートを `CtapHidProcessor.onReport` へ (65 バイトで先頭 0 ならレポート ID として除去、64 未満は 0 埋め) |
| `onGetReport` | 64 バイトのゼロを返す |
| 入力レポートの送信 | `sendReport(host, 0, report)` |

起動・停止のタイミング: `MainActivity.onStart` で設定が ON なら `start()`、設定 OFF または Activity 終了時に `stop()`。
