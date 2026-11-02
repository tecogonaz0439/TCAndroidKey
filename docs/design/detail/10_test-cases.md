# DD-10 テスト仕様

| 項目 | 内容 |
|---|---|
| 文書番号 | TCAK-DD-10 |
| 版数 | 1.0 |
| 作成日 | 2026-11-02 |
| 関連文書 | BD-08 テスト計画、docs/TESTING.md |

## 1. 単体テスト (UT)

実行: `./gradlew :fido-core:test` (39 件。2026-11-02 時点で全件成功)

### 1.1 CBOR (`CborTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-01 | encodesIntegersInShortestForm | 整数の最短表現 (0, 23, 24, 1000, 10^6, -1, -7, -100) | SEC-10 |
| UT-02 | encodesMapKeysInCtapCanonicalOrder | マップキーの canonical 順序 | FR-06 |
| UT-03 | roundTripsNestedStructures | 入れ子構造の往復 | |
| UT-04 | decodesKnownCtapGetInfoLikeVector | 既知のバイト列のデコード | |
| UT-05 | rejectsTruncatedInput | 途中で切れた入力を拒否 | SEC-10 |
| UT-06 | rejectsIndefiniteLength | 不定長を拒否 | SEC-10 |
| UT-07 | rejectsTrailingBytes | 末尾の余剰を拒否 | SEC-10 |
| UT-08 | decodeFirstReportsConsumedLength | 消費バイト数 | |
| UT-09 | rejectsHugeDeclaredLengths | データ長を超える宣言を拒否 | SEC-10 |

### 1.2 CTAP2 (`Ctap2AuthenticatorTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-10 | getInfoAdvertisesFido20WithBuiltInUv | versions、AAGUID、options (rk/uv/plat、clientPin なし) | FR-06 |
| UT-11 | makeCredentialThenGetAssertionWithAllowListVerifiesSignature | 登録 → allowList 認証。rpIdHash、フラグ、AAGUID、COSE 鍵、カウンタ、**署名を公開鍵で検証** | FR-04, FR-05 |
| UT-12 | selfAttestationIsSignedByCredentialKey | packed 自己アテステーションの署名検証 | FR-16 |
| UT-13 | discoverableCredentialsAreEnumeratedWithGetNextAssertion | パスキー 2 件の列挙、numberOfCredentials、user 情報、別 RP の除外 | FR-05 |
| UT-14 | registeringSameUserAgainReplacesDiscoverableCredential | 同一ユーザー再登録の置き換え | FR-04 |
| UT-15 | excludeListMatchReturnsCredentialExcluded | excludeList 一致で `0x19`、追加されない | FR-04 |
| UT-16 | noCredentialsForRp | 該当なしで `0x2E` | FR-05 |
| UT-17 | deniedPolicyBlocksRegistrationAndCreatesNothing | 認可拒否で `0x27`、鍵を作らない | FR-11, SEC-02 |
| UT-18 | silentAssertionHasNoUpUvFlagsAndDoesNotConsumeAuthorization | `up: false` でフラグ 0、ワンタイム非消費 | FR-13 |
| UT-19 | successfulOperationsAreReportedAsCompleted | 完了通知とイベント | FR-13, FR-17 |
| UT-20 | zeroLengthPinAuthProbeReturnsPinNotSet | 長さ 0 の pinAuth で `0x35` | |
| UT-21 | unsupportedAlgorithmIsRejected | ES256 なしで `0x26` | |
| UT-22 | missingParametersAndBadCbor | `0x14` / `0x12` / `0x01` | SEC-10 |
| UT-23 | resetIsDeniedUnlessEnabled | 設定 OFF で `0x27`、ON で全削除 | FR-10 |
| UT-24 | signCounterIncreasesMonotonically | カウンタの単調増加 | FR-05 |

### 1.3 NFC APDU (`NfcCtapProcessorTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-25 | selectReturnsVersion | SELECT で `FIDO_2_0` 9000 | FR-01 |
| UT-26 | selectIsRejectedWhenGateClosed | ゲート不通過で `6A82`、以降も `6A82` | SEC-04 |
| UT-27 | otherAidIsNotFound | 他 AID で `6A82` | |
| UT-28 | ctapMsgWithoutSelectFails | SELECT 前の MSG で `6A82` | |
| UT-29 | commandChainingAssemblesRequest | コマンドチェイニングの結合 | FR-01 |
| UT-30 | longResponseIsChainedWithGetResponse | 700 バイト応答の 61XX / GET RESPONSE | FR-01 |
| UT-31 | extendedLengthApduIsAccepted | 拡張長 APDU | FR-01 |
| UT-32 | endToEndGetInfoOverApdu | APDU 経由の GetInfo | FR-01, FR-06 |
| UT-33 | u2fApduIsNotSupported | U2F で `6D00` | |

### 1.4 CTAPHID (`CtapHidProcessorTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-34 | initAllocatesChannelAndPingEchoesMultiPacketPayload | INIT の CID 払い出し、複数パケットの PING | FR-02 |
| UT-35 | cborGetInfoWithKeepalive | CBOR (GetInfo) と KEEPALIVE | FR-02 |
| UT-36 | unknownChannelIsRejected | 未払い出し CID で INVALID_CHANNEL | SEC-10 |
| UT-37 | ctap1MsgIsNotSupported | MSG で INVALID_CMD | |
| UT-38 | wrongSequenceAbortsTransaction | SEQ 不一致で INVALID_SEQ | SEC-10 |
| UT-39 | cancelWhileBusyInvokesCallback | 処理中の CANCEL | FR-02 |

## 2. CTAP 結合試験 (CT)

`scripts/test/fido2_nfc_test.py` (python-fido2 + PC/SC) を ENV-01 / ENV-02 で実行する。

| ID | 手順 | 期待結果 | 要件 |
|---|---|---|---|
| CT-01 | 本人確認後にリーダーへ載せ `--info` を実行 | versions `['FIDO_2_0']`、AAGUID、options が表示される | FR-01, FR-06 |
| CT-02 | 引数なしで実行 (登録 → 再度本人確認 → 認証) | MakeCredential のフラグに UP・UV・AT、GetAssertion の署名検証 OK、counter ≥ 1 | FR-04, FR-05 |
| CT-03 | アテステーションを「自己アテステーション」にして CT-02 | fmt = packed、署名検証 OK | FR-16 |
| CT-04 | 本人確認せずに `--info` | デバイスが見つからない (SELECT 拒否)、端末に本人確認ダイアログ | FR-15, SEC-04 |

## 3. 実機試験 (IT)

テスト用 RP (例: https://webauthn.io) とテスト用アカウントを使う (PRE-01, PRE-02)。

| ID | 項目 | 手順 | 期待結果 | 要件 |
|---|---|---|---|---|
| IT-01 | パスキー登録 | Discoverable = Required、UV = Preferred で登録 | 成功。SC-02 に「パスキー」で表示 | FR-04, FR-07 |
| IT-02 | パスキー認証 | ユーザー名を入力せずに認証 | 成功 | FR-05 |
| IT-03 | 非検出クレデンシャル | Discoverable = Discouraged で登録・認証 | 成功。「非検出」で表示 | FR-04, FR-05 |
| IT-04 | 複数アカウント | 同一 RP に 2 ユーザー登録 → ユーザー名なしで認証 | アカウント選択が表示され、選んだユーザーで成功 | FR-05 |
| IT-05 | 重複登録 | 同じユーザーを excludeCredentials 付きで再登録 | RP / クライアントが拒否 | FR-04 |
| IT-06 | 本人確認前のタップ | 本人確認せずにかざす → 確認 → 再度かざす | 1 回目は反応なし + 本人確認ダイアログ、2 回目で成功 | FR-11, FR-15 |
| IT-07 | バックグラウンド | ホーム画面に戻してからかざす | 反応しない。ログ "not in the foreground" | FR-14, SEC-04 |
| IT-08 | 受付時間切れ | 受付時間 15 秒にして、20 秒後にかざす | 反応しない | FR-12 |
| IT-09 | ワンタイム | ワンタイム ON で連続 2 回認証 | 2 回目は本人確認が必要 | FR-13 |
| IT-10 | ワンタイム OFF | OFF (本人確認あり) で受付時間内に 2 回認証 | 2 回とも成功 | FR-13, SEC-09 |
| IT-11 | 端末ロック | 受付中に画面をロックしてかざす | 反応しない | SEC-03 |
| IT-12 | 個別削除 | SC-02 で削除 (本人確認) → 認証 | 削除後は認証できない (NO_CREDENTIALS) | FR-08, SEC-09 |
| IT-13 | 全削除 | すべて削除 (本人確認) | 一覧が空になる | FR-09, SEC-09 |
| IT-14 | OS からのリセット | 設定 OFF で Windows のセキュリティキーリセット → ON にして再実行 | OFF: 拒否、ON: 全削除 | FR-10 |
| IT-15 | StrongBox | StrongBox 搭載機で登録 | 「StrongBox」と表示 | NFR-04 |
| IT-16 | 画面ロック未設定 | 画面ロックを外して起動 | 「画面ロックを設定」の表示。本人確認・登録不可 | SEC-02 |
| IT-17 | 生体認証のみ | ON にして本人確認 | PIN 等の選択肢が出ない | FR-18 |
| IT-18 | スクリーンショット | アプリ画面でスクリーンショット | 撮影できない | SEC-07 |
| IT-19 | 上書き更新 | 新しい debug APK を `adb install -r` | クレデンシャルが残る | NFR-10 |
| IT-20 | 言語 | 端末言語を英語 / 日本語に切り替え | 表示が切り替わる | NFR-07 |
| IT-21 | 画面幅 | タブレット / 横向き (840dp 以上) | 常設サイドバー表示・開閉 | NFR-09 |
| IT-22 | GMS 非搭載端末 | GMS のない端末で IT-01〜02 | 動作する | NFR-03 |
| IT-23 | Bluetooth (実験的) | 設定 ON → ペアリング → ブラウザで登録・認証 | 結果を記録 (動作保証外) | FR-02 |

## 4. 互換性マトリクス (CP)

試験結果を記録する。

| クライアント | 接続 | 登録 | 認証 | パスキー | 備考 |
|---|---|---|---|---|---|
| Windows 11 / Edge | NFC (RC-S300/P) | | | | |
| Windows 11 / Chrome | NFC (RC-S300/P) | | | | |
| Windows 11 / python-fido2 | NFC (RC-S300/P) | | | | |
| macOS 27 / python-fido2 | NFC (RC-S300/P) | | | | |
| macOS 27 / Safari | NFC (RC-S300/P) | | | | |
| macOS 27 / Chrome | NFC (RC-S300/P) | — | — | — | 非対応の想定 |
| Android 15+ / Chrome | NFC (端末同士) | | | | |
| Windows 11 / Edge・Chrome | Bluetooth HID | | | | 実験的 |
| macOS 27 / Safari・Chrome | Bluetooth HID | | | | 実験的 |

## 5. 要件とテストの対応

| 要件 | テスト |
|---|---|
| FR-01 | UT-25〜33, CT-01 |
| FR-02 | UT-34〜39, IT-23 |
| FR-04 / FR-05 | UT-11, 13〜16, 24, CT-02, IT-01〜05 |
| FR-06 | UT-10, 32, CT-01 |
| FR-07〜FR-09 | IT-01, 12, 13 |
| FR-10 | UT-23, IT-14 |
| FR-11〜FR-15 | UT-17〜19, 26, CT-04, IT-06〜10 |
| FR-16 | UT-12, CT-03 |
| FR-17 / FR-18 | UT-19, IT-17 |
| NFR-03 / 04 / 07 / 09 / 10 | IT-22 / IT-15 / IT-20 / IT-21 / IT-19 |
| SEC-02〜SEC-04 | UT-17, 26, IT-07, 08, 11, 16 |
| SEC-07 / SEC-09 / SEC-10 | IT-18 / IT-10, 12, 13 / UT-05〜07, 09, 22, 36, 38 |
