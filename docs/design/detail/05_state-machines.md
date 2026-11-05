# DD-05 状態遷移

| 項目 | 内容 |
|---|---|
| 文書番号 | TCSKE-DD-05 |
| 版数 | 1.2 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.2 (2026-11-05): §2.5 pinUvAuthToken と受付ゲートの関係を追加 |
| 改訂 | 1.1 (2026-11-02): 外部レビュー対応。認可を全トランスポート共有の `AuthorizationGate` に集約し、Lease・取消トークン・接続世代を導入 (`review/FIX_PLAN.md`) |
| 実装 | `fido-core/.../session/AuthorizationGate.kt`, `app/.../auth/AuthSessionManager.kt`, `MainActivity.kt`, `bluetooth/BluetoothHidAuthenticator.kt`, `fido-core/.../nfc/NfcCtapProcessor.kt`, `app/.../nfc/FidoHostApduService.kt` |
| 関連要件 | FR-11〜FR-15, FR-22, SEC-02, SEC-04 |

## 1. 時刻の基準

受付期限は `SystemClock.elapsedRealtime()` (起動からの経過時間、端末の時刻変更の影響を受けない) で管理する。
最終使用日時など表示用の時刻は `System.currentTimeMillis()` を用いる。
GetNextAssertion のタイマーも単調時計 (`System.nanoTime()` 基準) で計る (DD-01 §5)。

## 2. 認証受付セッション

受付状態・ワンタイムの予約・失効は、全トランスポート (NFC / Bluetooth) で共有する `AuthorizationGate` (fido-core、
Android 非依存) が 1 つのロックで管理する。`AuthSessionManager` は Android の時計・設定・ログ・UI への確認要求との
橋渡しをする薄い層である。

### 2.1 状態

`SessionState` (`AuthSessionState` はその別名) の `foreground` と `armedUntilElapsed` の組み合わせで決まる。
内部状態として、世代 `epoch`、受付番号 `armId`、ワンタイムの予約 `reservation` を持つ。

| 状態 | foreground | armedUntilElapsed | 認証 |
|---|---|---|---|
| 非表示 (BACKGROUND) | false | null | 拒否 |
| 待機 (IDLE) | true | null または期限切れ | 拒否 (本人確認を要求) |
| 受付中 (ARMED) | true | 現在時刻より後 | 許可 (ワンタイム ON で予約中の場合は拒否 / 待機) |

```mermaid
stateDiagram-v2
    [*] --> BACKGROUND
    BACKGROUND --> IDLE: onStart (setForeground true)
    IDLE --> BACKGROUND: onStop
    IDLE --> ARMED: 本人確認成功 (arm)
    ARMED --> IDLE: 受付時間経過
    ARMED --> IDLE: 「停止」(disarm, epoch+1)
    ARMED --> IDLE: ワンタイム消費 (登録/認証成功)
    ARMED --> BACKGROUND: onStop (受付も解除, epoch+1)
```

### 2.2 遷移の詳細

| 操作 | 処理 |
|---|---|
| `setForeground(true)` | `foreground = true` (受付期限は保持する。画面ロック資格情報による本人確認では一時的に別画面が前面になるため) |
| `setForeground(false)` | `foreground = false`、`armedUntilElapsed = null`、**`epoch` を進め予約を解放** (発行済み Lease はすべて失効)、待機中のブロッキング認可を起こす |
| `arm(duration)` | `armId` を進め、`armedUntilElapsed = 現在 + 受付時間`。ログ "verified: accepting authentication for Ns" |
| `disarm()` (明示的な停止) | `armedUntilElapsed = null`、**`epoch` を進め予約を解放**。受付中だった場合ログ "authorization ended: …" |
| `Lease.complete(consumed = true)` | 予約を解放し、`lastAuthenticationAtMillis` / `RpId` を更新。ワンタイム ON かつ **Lease の `armId` が現在の受付と一致する場合のみ** 受付を終了する (`epoch` は進めない) |
| `Lease.complete(consumed = false)` | 予約を解放するだけ (受付は継続) |

> 受付時間の経過は時刻比較 (`isArmed(now)`) で判定し、タイマーは使わない。画面のカウントダウンは 250 ms 毎に再描画する。

### 2.3 認可判定 (AuthorizationGate.authorize)

```mermaid
flowchart TD
    A["authorize(request, keepAlive, blocking)"] --> X{"keepAlive.isCancelled?"}
    X -- Yes --> D0["Denied 0x2D"]
    X -- No --> B{"foreground?"}
    B -- No --> D1["Denied 0x27<br/>app is not in the foreground"]
    B -- Yes --> C{"isArmed かつ 予約なし?"}
    C -- Yes --> G["Lease を発行 (ワンタイム ON なら予約)<br/>Granted(UP, UV, lease)"]
    C -- No --> E{"blocking?"}
    E -- "No (NFC)" --> D2["未確認: 本人確認を要求し Denied 0x27<br/>予約中: Denied 0x27 another operation"]
    E -- "Yes (Bluetooth)" --> W["未確認なら本人確認を要求し待機"]
    W --> L{"状態変化 / 100 ms 毎に判定"}
    L -- "取消 (CANCEL・切断)" --> D3["Denied 0x2D"]
    L -- "foreground 喪失" --> D4["Denied 0x27"]
    L -- "isArmed かつ 予約なし" --> G
    L -- "30 秒経過" --> D5["Denied 0x2F"]
    L -- "継続" --> K["KEEPALIVE UPNEEDED 送信"] --> L
```

- 判定と予約は同じロック内で行う。NFC と Bluetooth から同時に要求されても、ワンタイム ON では 1 つの操作にしか許可しない。
  ワンタイム OFF では予約しない (同時処理を許可する)。
- 本人確認要求 (`requestVerification`) は、前面表示中かつ設定「確認前にかざしたら確認画面を表示」が ON の場合のみ発行する。
  予約中 (他の操作の実行中) を理由に拒否する場合は要求しない。
- Activity は要求を受けたとき、本人確認ダイアログを表示中でなく、受付中でもない場合に限りダイアログを表示する。

### 2.4 操作の寿命 (Lease・取消トークン)

許可した 1 つの操作 (MakeCredential、GetAssertion とそれに続く GetNextAssertion 群、Reset、Selection) は
`AuthorizationLease` で管理する。トランスポートは要求ごとに取消トークン (`KeepAlive.isCancelled`) を作って渡す。

| 項目 | 内容 |
|---|---|
| `Lease.isValid()` | `foreground` かつ発行時の `epoch` が現在と一致。明示的な停止・前面離脱で false。ワンタイムの消費では false にならない |
| 有効性の確認箇所 | 鍵の生成の直前、署名の直前、応答を返す直前 (`Ctap2Authenticator.ensureActive`) |
| 失効時の動作 | `CTAP2_ERR_OPERATION_DENIED` を返す。生成済みで応答していない credential は削除する |
| 取消トークン | NFC: 受信時の接続世代 (DD-02 §6)。Bluetooth: CBOR 要求ごとの操作 (DD-03 §2.4)。取消時は `CTAP2_ERR_KEEPALIVE_CANCEL` |
| 完了 | すべての経路 (成功・失敗・excludeList 該当・PIN プローブ・NO_CREDENTIALS・例外) で `complete` を 1 回呼ぶ |
| 継続 (GetNextAssertion) | 元の GetAssertion の Lease・取消トークン・チャネル (CID) がすべて有効な場合のみ実行する |

```mermaid
sequenceDiagram
    participant T as トランスポート
    participant A as Ctap2Authenticator
    participant G as AuthorizationGate
    T->>A: process(request, token, channel)
    A->>G: authorize(request, token)
    G-->>A: Granted(lease) / Denied
    A->>A: ensureActive (token, lease)
    A->>A: 鍵生成 / 署名
    A->>A: ensureActive (token, lease)
    A->>G: lease.complete(consumed)
    A-->>T: 応答
    Note over G: disarm / setForeground(false) → epoch+1<br/>以降 lease.isValid() = false
```

### 2.5 pinUvAuthToken と受付ゲート

CTAP 2.1 の pinUvAuthToken (DD-01 §12.1) は、受付ゲートの認可を置き換えない。トークンの発行・トークンを使う操作のどちらでも
`AuthorizationGate.authorize` を呼ぶ。

| 操作 | 認可 | ワンタイム |
|---|---|---|
| トークンの発行 (ClientPIN 0x06) | `PIN_UV_AUTH_TOKEN` (UV 要)。受付外なら NFC は拒否、Bluetooth は本人確認を待つ | 消費しない (`complete(false)`) |
| トークンを使う登録・UP を伴う認証 | `MAKE_CREDENTIAL` / `GET_ASSERTION` | 消費する |
| トークンを使う silent assertion | `GET_ASSERTION` (UP なし) | 消費しない |
| 資格情報の管理 (CredentialManagement 0x0A) | `CREDENTIAL_MANAGEMENT`。列挙の続きは開始時の Lease で継続 | 消費しない |

トークンは発行時の Lease を保持し、`Lease.isValid()` が false になる (停止・前面離脱) と使えなくなる。
NFC の切断などで `Ctap2Authenticator.resetSession` が呼ばれた場合も使えなくなる (セッションの世代)。

```mermaid
sequenceDiagram
    participant C as クライアント (CTAP 2.1)
    participant A as Ctap2Authenticator
    participant G as AuthorizationGate
    C->>A: ClientPIN getKeyAgreement
    C->>A: ClientPIN getPinUvAuthTokenUsingUvWithPermissions (mc)
    A->>G: authorize(PIN_UV_AUTH_TOKEN)
    G-->>A: Granted(lease)
    A->>G: lease.complete(consumed = false)
    A-->>C: encrypt(pinUvAuthToken)
    C->>A: MakeCredential + pinUvAuthParam
    A->>A: トークンの検証 (使用中・HMAC・権限・RP ID)
    A->>G: authorize(MAKE_CREDENTIAL)
    G-->>A: Granted(lease)
    A->>A: 鍵生成・応答の作成、トークンの権限を消去
    A->>G: lease.complete(consumed = true)
    A-->>C: 登録結果
```

## 3. 本人確認ダイアログ

```mermaid
stateDiagram-v2
    [*] --> Hidden
    Hidden --> Check: 「本人確認して開始」/ 要求 / 削除・設定変更
    Check --> Hidden: 画面ロック未設定 / 生体認証なし (メッセージ表示)
    Check --> Showing: availability = AVAILABLE
    Showing --> Hidden: 成功 → 処理実行 (arm / 削除 / 設定変更)
    Showing --> Hidden: エラー・キャンセル (メッセージ表示)
```

| 設定 | 許可する認証手段 | キャンセルボタン |
|---|---|---|
| 生体認証のみ OFF (既定) | `BIOMETRIC_STRONG` + `DEVICE_CREDENTIAL` | なし (OS の UI) |
| 生体認証のみ ON | `BIOMETRIC_STRONG` | あり |

`UserVerifier` は表示中の二重表示を防ぐ (`isShowing`)。

## 4. NFC セッション (NfcCtapProcessor)

```mermaid
stateDiagram-v2
    [*] --> Unselected
    Unselected --> Selected: SELECT (AID 一致・ゲート通過)
    Unselected --> Unselected: SELECT 拒否 / その他 (6A82)
    Selected --> Chaining: NFCCTAP_MSG (CLA 90)
    Chaining --> Chaining: NFCCTAP_MSG (CLA 90)
    Chaining --> Responding: NFCCTAP_MSG (CLA 80) → CTAP 処理
    Selected --> Responding: NFCCTAP_MSG (CLA 80) → CTAP 処理
    Chaining --> Selected: 不正な APDU / 別の命令 / GET RESPONSE (チェーン破棄)
    Responding --> Responding: GET RESPONSE CLA 00/80 (残りあり 61XX)
    Responding --> Responding: GET RESPONSE の P1/P2 不正 (6A86、応答は保持)
    Responding --> Selected: 最終チャンク送信 (9000)
    Responding --> Selected: 他のコマンド (未送信破棄)
    Selected --> Unselected: onDeactivated / SELECT
    Chaining --> Unselected: onDeactivated
    Responding --> Unselected: onDeactivated
```

拡張長 APDU の要求には、応答全体を拡張長の応答として一度に返すため、Responding を経由しない
(Le が明示的に応答より短い場合を除く。DD-02 §3.2)。

## 5. Bluetooth HID

```mermaid
stateDiagram-v2
    [*] --> STOPPED
    [*] --> UNSUPPORTED: アダプタなし
    STOPPED --> PERMISSION_REQUIRED: start (権限なし)
    PERMISSION_REQUIRED --> STARTING: 権限許可 → start
    STOPPED --> BLUETOOTH_OFF: start (Bluetooth オフ)
    STOPPED --> STARTING: start
    STARTING --> UNSUPPORTED: getProfileProxy 失敗
    STARTING --> ERROR: registerApp 失敗
    STARTING --> WAITING_FOR_HOST: onAppStatusChanged(registered)
    WAITING_FOR_HOST --> CONNECTED: ホスト接続
    CONNECTED --> WAITING_FOR_HOST: ホスト切断
    WAITING_FOR_HOST --> STOPPED: stop / OS による登録解除
    CONNECTED --> STOPPED: stop / OS による登録解除
    STOPPED --> STARTING: start (プロキシが残っていれば registerApp のみ再実行)
```

- プロキシの有無 (`hid`) と登録状態 (`registered`) は別に管理する。OS がバックグラウンド化などで登録を解除した場合、
  次の `start()` (アプリが前面に戻ったとき) で登録し直す。
- `stop()` の後に遅れて届いたプロキシ接続 (`onServiceConnected`) は、登録せずに閉じる (`desiredStarted`)。
- `stop()` は UI スレッドから呼ばれる。先に取消 (`CtapHidProcessor.reset()`) を行い、CTAP 処理のロックは待たない。
