# TCAndroidKey レビュー依頼プロンプト (ChatGPT Pro 用)

## 使い方

1. 下の「---- ここから ----」から「---- ここまで ----」までを、ChatGPT Pro に貼り付ける。
2. ソースコードは次のどちらかで渡す。
   - **A. GitHub 連携**: ChatGPT の GitHub コネクタでリポジトリ `tecogonaz0439/TCAndroidKey` を読めるようにする
     (ブランチ `claude/friendly-sagan-ipwxxv`、コミット `ecd6e49`)。
   - **B. ZIP 添付**: 同時に配布した `TCAndroidKey-src-ecd6e49.zip` を添付する。
3. 回答が長くなる場合は「続けてください」で続きを出してもらう。
   観点ごと (機能 → セキュリティ → その他) に分けて依頼してもよい。

---- ここから ----

あなたは FIDO2 / WebAuthn (CTAP2) の仕様、Android アプリのセキュリティ、Android アプリ開発 (Kotlin / Jetpack Compose) に精通したシニアレビュアーです。
以下の Android アプリ「TCAndroidKey」のソースコードと設計書をレビューし、**機能レビュー**・**セキュリティレビュー**・**その他 (ガイドライン準拠・品質)** の 3 観点で指摘事項を挙げてください。

## 1. 対象

| 項目 | 内容 |
|---|---|
| リポジトリ | https://github.com/tecogonaz0439/TCAndroidKey (ブランチ `claude/friendly-sagan-ipwxxv`、コミット `ecd6e49`)、または添付の ZIP |
| 概要 | Android 端末を FIDO2 (CTAP 2.0) のローミング認証器 (セキュリティキー) として振る舞わせるアプリ |
| 位置付け | **FIDO / FIDO2 を使用した Web アプリケーションのテスト用ツール**。YubiKey などの物理セキュリティキーの代替としては使用しない (本番アカウントには登録しない) |
| 接続方式 | NFC (HCE、主ターゲット)、Bluetooth HID (実験的)。USB は技術的に不可のため非対応 |
| 鍵保管 | Android Keystore (StrongBox 優先、なければ TEE)。クレデンシャル毎に EC P-256 鍵 |
| 認可 | アプリが前面表示中 (Activity onStart〜onStop) かつ BiometricPrompt による本人確認から設定秒数 (15〜300 秒、既定 60) の間のみ。既定は 1 回の登録/認証で受付終了 (ワンタイム) |
| 技術スタック | Android 15+ (minSdk 35, targetSdk/compileSdk 37)、Kotlin 2.4、AGP 9.3 (組み込み Kotlin)、Jetpack Compose (BOM 2026.08, Material 3)、AndroidX のみ (Google Play 開発者サービス・DI フレームワーク不使用) |
| 状態 | クラウドでビルド・単体テスト (39 件) ・lint (エラー 0) 成功。実機ではアプリの起動まで確認済み。NFC 等での実機試験はこれから |

### 1.1 まず読んでほしいファイル

| 区分 | パス |
|---|---|
| 設計書 (目次) | `docs/design/README.md` |
| 要件・前提 | `docs/design/basic/01_system-overview.md`, `docs/design/basic/02_requirements.md` |
| セキュリティ方針 | `docs/design/basic/05_security.md` |
| プロトコル詳細 | `docs/design/detail/01_ctap2.md`, `02_nfc.md`, `03_bluetooth-hid.md` |
| 状態遷移・鍵管理 | `docs/design/detail/05_state-machines.md`, `07_key-management.md` |
| 既知の制約 | `docs/design/appendix/C_roadmap.md` |

### 1.2 主要なソースコード

| 区分 | パス |
|---|---|
| CBOR | `fido-core/src/main/kotlin/net/tecogonaz/tcandroidkey/fido/cbor/Cbor.kt` |
| CTAP2 認証器 | `fido-core/src/main/kotlin/.../fido/ctap2/Ctap2Authenticator.kt`, `CredentialStore.kt`, `AuthorizationPolicy.kt`, `CtapConstants.kt` |
| NFC APDU | `fido-core/src/main/kotlin/.../fido/nfc/NfcCtapProcessor.kt` |
| CTAPHID | `fido-core/src/main/kotlin/.../fido/hid/CtapHidProcessor.kt` |
| 単体テスト | `fido-core/src/test/kotlin/...` |
| Keystore | `app/src/main/java/net/tecogonaz/tcandroidkey/keystore/KeystoreCredentialStore.kt`, `MetadataStore.kt` |
| 認可・本人確認 | `app/src/main/java/.../auth/AuthSessionManager.kt`, `UserVerifier.kt` |
| HCE | `app/src/main/java/.../nfc/FidoHostApduService.kt`, `app/src/main/res/xml/apduservice.xml` |
| Bluetooth HID | `app/src/main/java/.../bluetooth/BluetoothHidAuthenticator.kt` |
| Activity / UI | `app/src/main/java/.../MainActivity.kt`, `AppContainer.kt`, `ui/**` |
| マニフェスト・ビルド | `app/src/main/AndroidManifest.xml`, `app/build.gradle.kts`, `gradle/libs.versions.toml`, `app/src/main/res/xml/data_extraction_rules.xml` |

## 2. レビュー観点

### 2.1 機能レビュー (プロトコル実装の正しさ・相互運用性)

FIDO2 / WebAuthn / CTAP の仕様 (CTAP 2.0 / 2.1、WebAuthn Level 2/3、ISO 7816-4) に照らして、次を確認してください。

1. **CTAP2 コマンド**
   - authenticatorGetInfo の内容 (versions `FIDO_2_0`、options `rk/up/uv/plat`、clientPin を出さないこと、maxMsgSize、transports、algorithms) は妥当か。clientPIN 非対応・内蔵 UV のみという構成で、Windows WebAuthn / Chrome (Android) / python-fido2 と相互運用できるか
   - authenticatorMakeCredential: パラメータ検証の順序とエラーコード、pubKeyCredParams の選択、excludeList の扱い (UP を得てから CREDENTIAL_EXCLUDED を返す挙動)、`rk` / `uv` / `up` オプション、同一 RP・同一ユーザー ID の discoverable credential の上書き、user.id の長さ検証
   - authenticatorGetAssertion: allowList あり/なしの検索、discoverable credential の並び順、`numberOfCredentials` と authenticatorGetNextAssertion の状態管理 (タイムアウト・他コマンドを挟んだ場合の破棄)、`up: false` (silent assertion) の扱い、応答の `user` に含める情報 (UV 済みの場合のみ name / displayName)
   - pinAuth / pinUvAuthParam の扱い (長さ 0 → PIN_NOT_SET、それ以外 → PIN_AUTH_INVALID) は仕様と実在クライアントの挙動に照らして妥当か
   - authenticatorReset (設定で許可時のみ) / authenticatorSelection の扱い
   - 非対応コマンド (ClientPIN, CredentialManagement 等) の応答
2. **データ構造**
   - authenticatorData (rpIdHash、フラグ UP/UV/AT、signCount、attestedCredentialData)、COSE_Key (EC2 / P-256 / ES256) のエンコード
   - CTAP2 canonical CBOR (整数の最短表現、マップキーの順序) の実装、デコーダの堅牢性
   - アテステーション: `none` と `packed` 自己アテステーション (x5c なし、クレデンシャル鍵で署名) の構造
   - 署名カウンタの扱い (クレデンシャル毎、署名直前に +1)
3. **NFC (FIDO NFC プロトコル / ISO 7816-4)**
   - SELECT 応答 (`FIDO_2_0`)、NFCCTAP_MSG、コマンドチェイニング (CLA 0x90)、レスポンスチェイニング (61XX + GET RESPONSE)、短い APDU / 拡張長 APDU の解析
   - 受付外の場合に SELECT へ `6A82` を返して「FIDO アプレットが存在しない」ように振る舞う設計の妥当性 (クライアントの再試行挙動を含む)
   - NFCCTAP_GETRESPONSE (0x9100) を使わない設計の妥当性
   - HostApduService のスレッド処理 (ワーカーで処理し `sendResponseApdu`)、onDeactivated での状態破棄
4. **CTAPHID (Bluetooth HID、実験的)**
   - INIT / チャネル払い出し / PING / CBOR / CANCEL / KEEPALIVE / ERROR、パケット組み立て (SEQ、タイムアウト、BUSY)、レポートディスクリプタ
   - Android `BluetoothHidDevice` の使い方 (登録・レポート送受信・レポート ID の扱い) と、Windows / macOS のホストで FIDO HID デバイスとして認識されるか
5. **テスト**: 単体テストの網羅性、不足しているテストケース (特に異常系・境界値・相互運用性)

### 2.2 セキュリティレビュー (脆弱性・設計上の弱点)

テスト用ツールであることを前提に、「テストで使う鍵が利用者の意図しないタイミング・相手に使われないこと」「鍵やテスト用アカウント情報が端末外へ流出しないこと」を目的としています (`docs/design/basic/05_security.md`)。次を確認してください。

1. **認可ゲート**
   - 「前面表示中」の判定 (onStart/onStop)、BiometricPrompt 成功後の受付、受付時間の判定 (`elapsedRealtime`)、ワンタイムの消費タイミングに抜け・競合状態 (TOCTOU) がないか。例: SELECT 受理後〜CTAP 処理の間、マルチウィンドウ / ピクチャーインピクチャー / 画面オフ、画面ロック資格情報による確認中に別 Activity が前面になる場合
   - silent assertion (`up: false`) や excludeList 照合・GetNextAssertion がワンタイムを消費しないことによる悪用の余地
   - NFC で受付時間内に第三者のリーダー (リレー攻撃を含む) から要求された場合のリスクと、追加すべき緩和策
2. **Android Keystore**
   - 鍵生成パラメータ (`setUserAuthenticationParameters(300, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`、`setUnlockedDeviceRequired`、StrongBox フォールバック) の妥当性
   - CryptoObject を使わない BiometricPrompt と時間制限付き鍵の組み合わせ (端末のロック解除でも認証トークンが発行される点) の評価、より良い方式があるか
   - メタデータの暗号化 (AES-256-GCM、`AtomicFile`)、改ざん・巻き戻し (署名カウンタのロールバック) への耐性、キャッシュとファイルの整合性
3. **入力検証・DoS**: CBOR デコーダ (ネスト深さ・長さ)、APDU 解析、CTAPHID の組み立てで、クラッシュ・メモリ枯渇・無限ループ・例外の取りこぼしがないか
4. **Android コンポーネントの公開範囲**: exported なコンポーネント、HCE サービスの保護 (`BIND_NFC_SERVICE`)、Intent の扱い、他アプリからの悪用の余地
5. **Bluetooth**: 権限 (`BLUETOOTH_CONNECT` / `BLUETOOTH_ADVERTISE`)、ペアリング・接続の受け入れ方 (任意のホストが接続できてしまう等)、HID 登録の持続
6. **情報漏えい**: ログ (logcat を含む) に含まれる RP ID・ユーザー名、`FLAG_SECURE`、バックアップ除外 (`allowBackup=false`、data extraction rules)、例外メッセージ
7. **ビルド・配布**: リポジトリに同梱した開発用 debug 署名鍵 (`app/debug.keystore`) の扱い、release ビルド設定 (R8、署名)、依存ライブラリ
8. **暗号実装**: 乱数 (credential ID)、署名形式 (DER)、ハッシュ、Kotlin/JVM 上の定数時間比較が必要な箇所の有無

### 2.3 その他 (Android ガイドライン準拠・品質)

1. **Android の各種ガイドライン・ベストプラクティス**: 実行時権限、targetSdk 37 での動作変更への対応、Activity / Service のライフサイクル、HCE (category `other`、優先サービス設定)、Bluetooth の利用、エッジツーエッジ、予測型「戻る」ジェスチャー
2. **Jetpack Compose / Material 3**: 状態管理 (StateFlow / collectAsStateWithLifecycle)、再コンポーズの無駄 (`setContent` 内の `enableEdgeToEdge` 呼び出し等)、Navigation の使い方、レスポンシブ対応 (840dp で常設サイドバー)
3. **アクセシビリティ**: TalkBack、コントラスト、タッチターゲット、live region
4. **国際化**: 文字列リソース (英語・日本語)、複数形、日付書式
5. **スレッド・並行性**: メインスレッドでの重い処理、`@Synchronized` / ロックの使い方、デッドロックの可能性、コルーチンのスコープ
6. **保守性**: モジュール分割 (Android 非依存の `fido-core`)、手動 DI、テスト容易性、コードの重複・不要コード
7. **ビルド**: Gradle 設定 (AGP 9 の組み込み Kotlin、バージョンカタログ)、lint 設定、ProGuard/R8 ルール

## 3. 既知の制約 (指摘不要)

次は仕様上の割り切りとして把握済みです。**これ自体を不具合として挙げる必要はありません**。
ただし、これらが原因で相互運用性やセキュリティに具体的な問題が生じる場合は指摘してください。

- clientPIN 非対応、CTAP 2.1 非対応 (versions は `FIDO_2_0` のみ)、U2F (CTAP1) 非対応
- WebAuthn 拡張 (hmac-secret, credProtect, largeBlob 等) 非対応、ES256 のみ
- ベンダーアテステーションなし (none / 自己アテステーション)、AAGUID は MDS 未登録
- 鍵のバックアップ・移行不可、アンインストールで鍵消失
- USB 非対応 (技術的に不可)、Bluetooth HID は実験的
- NFC で本人確認前にかざした場合は 2 回かざす必要がある
- テスト用ツールであり、FIDO 認定水準の耐タンパ性は目標としない

## 4. 回答形式

日本語で、次の形式で回答してください。

### 4.1 総評

全体の評価を 5〜10 行で。最も重要な問題を 3 つまで挙げる。

### 4.2 指摘一覧 (表)

| ID | 観点 | 重大度 | 確度 | 対象 (ファイル:行 / 関数) | 概要 |
|---|---|---|---|---|---|

- ID: 機能 `F-nn`、セキュリティ `S-nn`、その他 `O-nn`
- 重大度: **Critical** (鍵の不正使用・流出、認可の回避) / **High** (主要な相互運用性の破綻、重大な脆弱性) / **Medium** / **Low** / **Info** (改善提案)
- 確度: **確実** (コードと仕様から断定できる) / **可能性あり** (条件次第・実機確認が必要)

### 4.3 指摘の詳細

各指摘について次を記載してください。

1. 内容 (何が問題か)
2. 根拠 (該当コードの抜粋、仕様の章番号・該当箇所)
3. 影響 (どのクライアント・条件で何が起きるか)
4. 再現・確認方法 (可能なら具体的な APDU / CBOR / 操作手順)
5. 修正案 (Kotlin のコード例、または設計の変更案)

### 4.4 その他

- 確認できなかった点・判断に実機試験が必要な点
- 追加すべきテストケース (単体テスト・実機試験)
- 修正の優先順位 (推奨する対応順)

## 5. 注意事項

- コードを実際に読んだうえで、具体的な箇所を示して指摘してください。一般論だけの指摘は「Info」としてください。
- 仕様の記述と実在クライアント (Windows WebAuthn、Chrome / Google Play 開発者サービスの FIDO 実装、python-fido2、libfido2) の実際の挙動が異なる場合は、両方を示してください。
- 確信が持てない内容は推測であることを明記してください。

---- ここまで ----
