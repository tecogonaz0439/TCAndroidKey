# DD-10 テスト仕様

| 項目 | 内容 |
|---|---|
| 文書番号 | TCSKE-DD-10 |
| 版数 | 1.7 |
| 作成日 | 2026-11-02 |
| 改訂 | 1.7 (2026-11-05): clientPIN の単体テスト (UT-157〜167)、CT-09、IT-36・IT-37 を追加。UT-10・UT-123・CT-07 を更新 |
| 改訂 | 1.6 (2026-11-05): CTAP 2.1 の単体テスト (UT-132〜156)、CT-07・CT-08 を追加。UT-10・UT-123・UT-128・CT-01・§4 を更新 |
| 改訂 | 1.5 (2026-11-05): hmac-secret の単体テスト (UT-123〜131)、CT-06 を追加。UT-10・UT-107・CT-05 を更新 |
| 改訂 | 1.4 (2026-11-05): PIN/UV Auth Protocol の単体テスト (UT-112〜122) を追加。UT-107・CT-05 に Protocol 1 / 2 の照合を追加 |
| 改訂 | 1.3 (2026-11-03): IT-35 (利用規約・セキュリティポリシー)、UT-108〜111 (app の単体テスト) を追加 |
| 改訂 | 1.2 (2026-11-02): IT-33 (言語設定)、IT-34 (注意書き) を追加 |
| 改訂 | 1.1 (2026-11-02): 外部レビュー対応のテスト (UT-39 置き換え、UT-40〜107、CT-05、IT-24〜32、互換性マトリクスの版・API 層)。`review/FIX_PLAN.md` |
| 関連文書 | BD-08 テスト計画、docs/TESTING.md |

## 1. 単体テスト (UT)

実行: `./gradlew :fido-core:test testDebugUnitTest` (計 167 件: fido-core 163 件、app 4 件。うち UT-107・UT-156 は環境変数指定時のみ実行。2026-11-05 時点で全件成功)

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
| UT-40 | rejectsNonCanonicalIntegerAndLengthEncodings | 最短でない整数・長さ (`18 01`、`19 00 17`、`58 01 …` 等) を拒否 | SEC-10 |
| UT-41 | rejectsTags | タグ (`C0 A0` 等) を拒否 | SEC-10 |
| UT-42 | rejectsInvalidUtf8 | 不正な UTF-8 (`61 FF` 等) を拒否 | SEC-10 |

### 1.2 CTAP2 (`Ctap2AuthenticatorTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-10 | getInfoAdvertisesFido20And21WithBuiltInUvAndClientPin | versions `["FIDO_2_0", "FIDO_2_1"]`、AAGUID、options (rk/uv/plat、pinUvAuthToken・credMgmt・makeCredUvNotRqd、PIN 未設定の clientPin false)、minPINLength 4、extensions `["credProtect", "hmac-secret"]`、pinUvAuthProtocols `[2, 1]` | FR-06, FR-21〜25 |
| UT-11 | makeCredentialThenGetAssertionWithAllowListVerifiesSignature | 登録 → allowList 認証。rpIdHash、フラグ、AAGUID、COSE 鍵、カウンタ、**署名を公開鍵で検証** | FR-04, FR-05 |
| UT-12 | selfAttestationIsSignedByCredentialKey | packed 自己アテステーションの署名検証 | FR-16 |
| UT-13 | discoverableCredentialsAreEnumeratedWithGetNextAssertion | パスキー 2 件の列挙、numberOfCredentials、user 情報、別 RP の除外 | FR-05 |
| UT-14 | registeringSameUserAgainReplacesDiscoverableCredential | 同一ユーザー再登録の置き換え | FR-04 |
| UT-15 | excludeListMatchReturnsCredentialExcluded | excludeList 一致で `0x19`、追加されない | FR-04 |
| UT-16 | noCredentialsForRp | 該当なしで `0x2E` | FR-05 |
| UT-17 | deniedPolicyBlocksRegistrationAndCreatesNothing | 認可拒否で `0x27`、鍵を作らない | FR-11, SEC-02 |
| UT-18 | silentAssertionHasNoUpUvFlagsAndDoesNotConsumeAuthorization | `up: false` でフラグ 0、ワンタイム非消費 (`complete(false)`) | FR-13 |
| UT-19 | successfulOperationsAreReportedAsCompleted | Lease の完了 (consumed) とイベント | FR-13, FR-17 |
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
| UT-32 | endToEndGetInfoOverApdu | APDU 経由の GetInfo (versions に `FIDO_2_1` を含む) | FR-01, FR-06 |
| UT-33 | u2fApduIsNotSupported | U2F で `6D00` | |
| UT-43 | getResponseAcceptsCla80AndCla00 | GET RESPONSE を CLA `80` / `00` の両方で受け付ける | FR-01 |
| UT-44 | responseLengthBoundaries | 応答 1 / 255 / 256 / 257 / 511 / 512 / 513 バイトの分割と再構成 | FR-01 |
| UT-45 | getResponseWithBadP1P2KeepsThePendingResponse | P1/P2 不正で `6A86`、未送信の応答は保持 | FR-01 |
| UT-46 | extendedRequestGetsTheWholeResponseAtOnce | 拡張長 (Le `0000` / 省略) に 1500 バイトを一括で応答 | FR-01 |
| UT-47 | extendedRequestWithExplicitShortLeIsChained | 拡張長で Le が短い場合のみ分割 | FR-01 |
| UT-48 | chainIsDiscardedAfterAnUnsupportedInstruction | チェーン中の未対応命令でチェーンを破棄 (次の要求に混入しない) | SEC-10 |
| UT-49 | chainIsDiscardedAfterAMalformedApduOrGetResponse | チェーン中の不正 APDU・GET RESPONSE でチェーンを破棄 | SEC-10 |
| UT-50 | packedSelfAttestationOverCla80GetResponse | 長い MakeCredential (チェイニング) の packed 自己アテステーションを `80 C0` で取得し署名検証 | FR-01, FR-16 |

### 1.4 CTAPHID (`CtapHidProcessorTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-34 | initAllocatesChannelAndPingEchoesMultiPacketPayload | INIT の CID 払い出し、複数パケットの PING | FR-02 |
| UT-35 | cborGetInfoWithKeepalive | CBOR (GetInfo) と KEEPALIVE | FR-02 |
| UT-36 | unknownChannelIsRejected | 未払い出し CID で INVALID_CHANNEL | SEC-10 |
| UT-37 | ctap1MsgIsNotSupported | MSG で INVALID_CMD | |
| UT-38 | wrongSequenceAbortsTransaction | SEQ 不一致で INVALID_SEQ | SEC-10 |
| UT-39 | cancelReceivedBeforeTheWorkerStartsIsNotLost | ワーカーの実行前に届いた CANCEL が取消トークンに反映され、元の要求に `0x2D` で応答 (1.0 の cancelWhileBusyInvokesCallback を置き換え) | FR-02 |
| UT-51 | cancelOnAnotherChannelIsIgnored | 別の CID からの CANCEL は無視 | FR-02 |
| UT-52 | initOnTheBusyChannelAbandonsTheOperation | 処理待ちの CID への INIT で操作を破棄し、応答を送らない。再同期後は BUSY にならない | FR-02 |
| UT-53 | resetDuringAnOperationSuppressesItsResponse | 処理中の reset で keepalive・応答を送らない | FR-02 |
| UT-54 | checkedExceptionFromTheHandlerReturnsErrorAndClearsBusy | 検査例外 (`IOException`) を `0x7F` に変換し BUSY を解放 | FR-02, SEC-10 |
| UT-55 | otherChannelIsBusyWhileAnOperationIsPending | 処理中は別 CID に CHANNEL_BUSY | FR-02 |
| UT-56 | lockIsNotImplemented | LOCK は `ERR_INVALID_CMD` | |
| UT-57 | channelIsPassedToTheAuthenticator | CID を CTAP2 処理へ渡す (GetNextAssertion の対応付け) | FR-05 |

### 1.5 認可ゲート (`AuthorizationGateTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-58 | deniedWhenNotForegroundOrNotVerified | 前面外・未確認で拒否、未確認時は本人確認を要求 | FR-11, FR-14 |
| UT-59 | armExpiresWithTime | 受付時間の経過で拒否 | FR-12 |
| UT-60 | oneTimeReservesTheWindowForASingleOperation | ワンタイム ON で 1 操作のみ許可 (予約中は "another operation"、本人確認は要求しない)、成功で受付終了 | FR-13 |
| UT-61 | failedOperationReleasesTheReservationWithoutConsuming | 失敗した操作は予約を解放し、受付は継続 | FR-13 |
| UT-62 | completeIsIdempotent | `complete` の 2 回目以降は無視 | FR-13 |
| UT-63 | withoutOneTimeConcurrentOperationsAreAllowed | ワンタイム OFF は同時に許可 | FR-13 |
| UT-64 | concurrentRequestsGetAtMostOneGrant | 8 スレッドの同時要求で許可は 1 件のみ | FR-13, SEC-02 |
| UT-65 | explicitStopAndBackgroundRevokeLeasesButConsumptionDoesNot | 停止・前面離脱で Lease 失効、消費では失効しない。前面復帰で古い Lease は戻らない | FR-14, SEC-02 |
| UT-66 | stopReleasesTheReservation | 停止で予約を解放 | FR-13 |
| UT-67 | staleCompletionDoesNotEndANewerWindow | 古い操作の完了で新しい受付を終了しない | FR-13 |
| UT-68 | cancelledRequestIsDeniedEvenWhenArmed | 取消済みの要求は受付中でも `0x2D` | FR-02 |
| UT-69 | blockingWaitsForVerification | ブロッキング型は本人確認まで待機 | FR-02, FR-11 |
| UT-70 | blockingWaitsForTheReservationToBeReleased | ブロッキング型は予約の解放まで待機 | FR-02, FR-13 |
| UT-71 | blockingStopsOnCancelAndOnLeavingForeground | 待機中の取消で `0x2D`、前面離脱で `0x27` | FR-02, FR-14 |
| UT-72 | cancelBeforeTheWaitStartsIsNotLost | 待機開始前の取消が失われない | FR-02 |
| UT-73 | blockingTimesOut | 待機のタイムアウトで `0x2F` | FR-02 |
| UT-74 | stateChangesAreReported | 状態変化・消費の通知 | FR-17 |

### 1.6 認可と CTAP 処理の結合 (`Ctap2AuthorizationTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-75 | noCredentialsIsReportedOnlyAfterAuthorization | 認可前に `0x2E` を返さない (存在確認の防止) | SEC-02 |
| UT-76 | everyGrantIsCompletedExactlyOnce | 成功・silent・excludeList・PIN プローブ・Selection のすべてで `complete` が 1 回 | FR-13 |
| UT-77 | revokedAuthorizationBeforeKeyGenerationCreatesNothing | 失効後は鍵を生成しない | SEC-02 |
| UT-78 | revocationAfterKeyGenerationDeletesTheNewCredential | 鍵生成後の失効で応答せず、生成した credential を削除 | SEC-02 |
| UT-79 | revocationAfterSigningSuppressesTheAssertion | 署名後の失効で応答しない | SEC-02 |
| UT-80 | cancelledRequestDoesNotUseKeys | 取消済みの要求は鍵を使わない | FR-02 |
| UT-81 | getNextAssertionRequiresAValidLease | Lease 失効後の GetNextAssertion は `0x30` | SEC-02 |
| UT-82 | getNextAssertionIsBoundToTheChannel | 別チャネルからの GetNextAssertion は `0x30` | FR-05 |
| UT-83 | getNextAssertionIsInvalidAfterTheOriginalRequestWasCancelled | 元の要求の取消 (切断) 後は `0x30` | FR-05 |
| UT-84 | checkedExceptionsFromTheStoreBecomeErrOther | ストアの検査例外を `0x7F` に変換 | SEC-10 |
| UT-85 | oneTimeAuthorizationCannotBeUsedByTwoTransportsAtOnce | 実際の `AuthorizationGate` で、NFC の処理中に Bluetooth の登録を拒否。完了後は消費済み | FR-13, SEC-02 |
| UT-86 | getNextAssertionContinuesAfterOneTimeConsumptionButNotAfterStop | ワンタイム消費後の列挙は継続、停止・前面離脱後は `0x30` | FR-13, FR-14 |

### 1.7 CTAP 2.0 の境界条件 (`Ctap2ConformanceTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-87 | allowListWithOnlyUnknownTypesDoesNotFallBackToDiscoverable | 未知 type のみの allowList は `0x2E` (discoverable 検索にしない) | FR-05 |
| UT-88 | emptyAllowListMeansDiscoverableSearch | 空の allowList は discoverable 検索 | FR-05 |
| UT-89 | mixedAllowListUsesKnownEntriesOnly | 既知・未知 type の混在 | FR-05 |
| UT-90 | upAndUvAreIndependent | UP/UV の全組み合わせのフラグとワンタイム消費 | FR-05, FR-13 |
| UT-91 | uvRequestFailsWhenVerificationWasNotPerformed | `uv: true` で UV 未実施なら `0x27` | FR-05 |
| UT-92 | clientDataHashMustBe32Bytes | 0 / 31 / 33 バイトで `0x03` | SEC-10 |
| UT-93 | extensionsMustBeAMapButUnknownExtensionsAreIgnored | extensions の型検証、未知の拡張は無視 | SEC-10 |
| UT-94 | pinProtocolMustBeAnInteger | pinProtocol の型検証 | SEC-10 |
| UT-95 | makeCredentialUpOption | 登録の `up: false` は `0x2C`、`up: true` は受け付ける | FR-04 |
| UT-96 | excludeListIsCheckedBeforeTheAlgorithm | excludeList 該当 + 未対応アルゴリズムで `0x19` | FR-04 |
| UT-97 | getNextAssertionTimerRestartsAfterEachAssertion | t = 0 / 20 / 40 秒で成功 (直前からの 30 秒) | FR-05 |
| UT-98 | getNextAssertionTimesOut | 30 秒超で `0x30` | FR-05 |
| UT-99 | failedGetNextAssertionDoesNotSkipTheCredential | 署名失敗後も同じ credential を取得できる | FR-05 |
| UT-100 | discoverableCredentialsAreReturnedNewestCreatedFirstRegardlessOfUse | 使用履歴に関係なく作成日時の新しい順 | FR-05 |
| UT-101 | newestFirstOrderingIsDeterministicForEqualTimestamps | 同時刻は ID 順 | FR-05 |

### 1.8 上書き登録・等価性 (`CredentialReplacementTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-102 | successfulOverwriteReplacesTheOldCredential | 上書き登録で旧 credential を削除、他ユーザーは残す | FR-04 |
| UT-103 | failedOverwriteKeepsTheOldCredential | 鍵生成の失敗で旧 credential が残る | FR-04 |
| UT-104 | failedAttestationKeepsTheOldCredentialAndRemovesTheNewOne | 自己アテステーションの失敗で旧 credential が残り、新しい鍵は削除 | FR-04, FR-16 |
| UT-105 | revokedOverwriteKeepsTheOldCredential | 認可の失効で旧 credential が残る | FR-04 |
| UT-106 | equalityIncludesCounterAndLastUse | カウンタ・最終使用日時の違いを別の値として扱う (UI の更新) | FR-07 |

### 1.9 外部検証器との照合 (`InteropVectorExport`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-107 | exportVectors | 環境変数 `TCSKE_INTEROP_OUT` 指定時のみ、GetInfo・packed 自己アテステーションの MakeCredential・GetAssertion の応答と、PIN/UV Auth Protocol 1 / 2 の照合用ベクタ (プラットフォーム鍵の秘密スカラー、認証器の公開鍵・暗号文・HMAC)、hmac-secret の往復 (登録 → salt 2 つの認証、CredRandom) を出力 (CT-05 で検証) | FR-04〜06, FR-16 |

### 1.10 文書のリンク解決 (`LegalDocumentTest`、app モジュール)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-108 | relativeLinksBetweenDocumentsStayInTheApp | 利用規約・セキュリティポリシー間の相対リンクをアプリ内の文書として解決 | FR-20 |
| UT-109 | otherRelativeLinksOpenTheRepository | その他の相対リンク (`../LICENSE`) を GitHub の URL に変換 | FR-20 |
| UT-110 | absoluteLinksAreOpenedAsIs | URL・`mailto:` はそのまま外部で開く | FR-20 |
| UT-111 | allRelativeLinksInTheDocumentsExist | 4 文書内の相対リンクがすべてリポジトリ内の実在するファイルを指す (リンク切れの検出) | FR-20 |

### 1.11 PIN/UV Auth Protocol (`PinUvAuthProtocolTest`)

プラットフォーム側は製品コードを使わないテスト用の実装 (`testutil.TestPlatform`) で照合する。外部の検証器との照合は CT-05。

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-112 | hkdfMatchesRfc5869TestVectors | HKDF-SHA-256 が RFC 5869 付録 A.1〜A.3 の PRK・OKM と一致 | — (基盤) |
| UT-113 | sharedSecretMatchesThePlatformSide | Protocol 1 / 2 の共有鍵がプラットフォーム側と一致 (32 / 64 バイト) | — (基盤) |
| UT-114 | encryptionRoundTripsWithThePlatform | 認証器 → プラットフォーム、プラットフォーム → 認証器の暗号化と復号 | — (基盤) |
| UT-115 | protocolOneUsesAZeroIvAndProtocolTwoARandomIv | Protocol 1 は IV 0 (同じ暗号文)、Protocol 2 はランダムな IV を先頭に付加 | — (基盤) |
| UT-116 | authenticateMatchesThePlatformAndVerifyRejectsTampering | HMAC (16 / 32 バイト) の一致、改ざん・長さ違い・別メッセージの拒否 | SEC-10 |
| UT-117 | tokensCanBeUsedAsHmacKeys | pinUvAuthToken を HMAC 鍵に使える (Protocol 1 は 16 / 32 バイト、Protocol 2 は 32 バイトのみ) | — (基盤) |
| UT-118 | regenerateChangesTheKeyAgreementKey | 鍵交換の鍵の作り直しで公開鍵と共有鍵が変わる | — (基盤) |
| UT-119 | publicKeyIsACoseEcdhKey | 公開鍵が COSE_Key (kty 2、alg -25、crv 1、32 バイトの座標、曲線上の点) | — (基盤) |
| UT-120 | invalidPeerKeysAreRejected | 曲線外の点、kty・crv・alg の不正、座標の長さ・型の不正、p 以上の座標を拒否 (alg の省略は許可) | SEC-10 |
| UT-121 | invalidCiphertextLengthsAreRejected | 16 の倍数でない・空の暗号文、IV のみの暗号文、鍵の長さの不正を拒否 | SEC-10 |
| UT-122 | createReturnsNullForUnknownVersions | 番号 1 / 2 以外のプロトコルは生成しない | — (基盤) |

### 1.12 hmac-secret と ClientPIN の鍵交換 (`HmacSecretTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-123 | getKeyAgreementReturnsACoseKeyAndRejectsInvalidRequests | getKeyAgreement の COSE_Key (Protocol 1 / 2)。Protocol 3 は `0x02`、欠落 `0x14`、型不正 `0x11`、getUVRetries (0x07)・未定義 (0x08) は `0x3E`。認可を求めない | FR-21, SEC-10 |
| UT-124 | makeCredentialReportsTheExtensionOnlyWhenRequested | `true` で ED と `{"hmac-secret": true}`、なし・`false` では出力も CredRandom もない、真偽値以外は `0x11` | FR-21 |
| UT-125 | getAssertionReturnsEncryptedOutputsForOneOrTwoSalts | salt 1 つ / 2 つの出力をプラットフォーム側で復号し `HMAC(CredRandomWithUV, salt)` と一致。ED が立ち、署名は拡張を含む authData で検証できる | FR-21 |
| UT-126 | outputsAreDeterministicPerSaltAndDifferWithoutUv | 同じ salt で同じ出力。UV なしの認証では CredRandomWithoutUV の出力 (UV ありと異なる) | FR-21 |
| UT-127 | protocolDefaultsToOneWhenOmitted | pinUvAuthProtocol を省略すると Protocol 1 | FR-21 |
| UT-128 | invalidInputsAreRejectedBeforeAuthorization | saltAuth 不一致 `0x33`、salt 長 48 バイト・未対応のプロトコル・曲線外の点 `0x02`、Protocol 1 で作った入力を Protocol 2 として送ると `0x33`、欠落 `0x14`、型不正 `0x11`、`up: false` `0x2B`。いずれも認可を求めない | FR-21, SEC-10 |
| UT-129 | credentialWithoutHmacSecretIgnoresTheExtension | hmac-secret なしの credential では出力を付けない | FR-21 |
| UT-130 | getNextAssertionReturnsOutputsForEachCredential | GetNextAssertion でも各 credential の CredRandom で出力 | FR-05, FR-21 |
| UT-131 | resetRegeneratesTheKeyAgreementKey | Reset で鍵交換の公開鍵が変わる | FR-10, FR-21 |

### 1.13 CTAP 2.1 の pinUvAuthToken (`Ctap21Test`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-132 | uvTokenIsIssuedThroughTheGateWithoutConsumingTheOneTimeAuthorization | Protocol 1 / 2 で 32 バイトのトークンを発行。認可は `PIN_UV_AUTH_TOKEN` (RP ID・UV 要) で、ワンタイムを消費しない | FR-22, FR-13 |
| UT-133 | uvTokenIsRefusedWhenTheGateDenies | 認可の拒否で `0x27`、UV を伴わない許可で `0x3F` | FR-22, SEC-02 |
| UT-134 | uvTokenRequestsAreValidatedBeforeAuthorization | permissions 0・未対応のプロトコル・曲線外の点 `0x02`、be / lbw / acfg `0x40`、欠落 `0x14`、型不正 `0x11`。いずれも認可を求めない | FR-22, SEC-10 |
| UT-135 | tokenAuthorizesMakeCredentialAndGetAssertionButTheGateIsStillConsulted | トークンによる登録・認証 (UV フラグ)。受付ゲートの認可を毎回求め、登録で消費する。使用後は権限が消える | FR-22, FR-13, SEC-02 |
| UT-136 | invalidPinUvAuthParamsAreRejected | HMAC の改ざん・プロトコルの取り違え・権限の不足・RP ID の不一致 `0x33`、プロトコルの欠落 `0x14`、未対応 `0x02` | FR-22, SEC-10 |
| UT-137 | tokenWithoutRpIdIsBoundOnFirstUse | RP ID なしのトークンは最初の使用で RP ID に結び付く | FR-22 |
| UT-138 | silentAssertionWithATokenHasUvButDoesNotConsumeTheOneTimeAuthorization | トークン付きの silent assertion は UV フラグのみで、ワンタイムを消費しない | FR-22, FR-13 |
| UT-139 | tokensExpireAndAreRevoked | 19 秒の未使用・600 秒の経過・セッションの変化・Lease の失効・新しいトークンの発行・Reset で使えなくなる | FR-22, SEC-02 |
| UT-140 | uvOptionStillWorksWithoutAToken | トークンを使わない 2.0 の経路 (`uv` オプション、長さ 0 のプローブ) が変わらない | FR-04, FR-05 |

### 1.14 credProtect (`CredProtectTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-141 | levelIsStoredAndReportedOnlyWhenRequested | レベルの保存と拡張の出力 (要求時のみ)、既定 1、0・4 は `0x02`、整数以外は `0x11` | FR-23 |
| UT-142 | levelThreeRequiresUserVerification | レベル 3 は UV なしの認証 (silent・UV なしの許可) で allowList があっても `0x2E` | FR-23 |
| UT-143 | levelTwoIsHiddenFromDiscoverableSearchWithoutUserVerification | レベル 2 は UV なしの discoverable の検索で除外、allowList 指定または UV ありなら使える | FR-23 |
| UT-144 | levelOneIsNeverFiltered | レベル 1 は常に使える | FR-23 |
| UT-145 | filteringKeepsOtherCredentialsInTheEnumeration | 除外後の credential だけを返す (numberOfCredentials なし) | FR-23, FR-05 |
| UT-146 | excludeListIgnoresLevelThreeCredentialsWithoutUserVerification | excludeList のレベル 3 は UV なしの認可では一致としない | FR-23, FR-04 |

### 1.15 credentialManagement (`CredentialManagementTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-147 | metadataCountsDiscoverableCredentials | discoverable の件数と残りの見積もり (non-discoverable は数えない) | FR-24 |
| UT-148 | requestsWithoutAValidCmTokenAreRejected | pinUvAuthParam なし `0x36`、プロトコルの欠落 `0x14`・未対応 `0x02`、検証失敗・認証対象の取り違え・cm 権限なし・RP ID 付きトークンでの件数取得と RP 列挙 `0x33`、未対応のサブコマンド `0x3E` | FR-24, SEC-10 |
| UT-149 | rpsAreEnumeratedInOrder | RP の列挙 (RP ID の昇順、rpIDHash、totalRPs)、終わりの後は `0x30` | FR-24 |
| UT-150 | credentialsOfAnRpAreEnumerated | credential の列挙 (新しい順、user・credentialID・publicKey・credProtect・totalCredentials)、該当なし `0x2E`、パラメータの欠落 `0x14`、RP ID 付きトークンはその RP のみ | FR-24, FR-23 |
| UT-151 | enumerationStateIsDiscardedByOtherCommandsTimeoutAndRevocation | 他のコマンド・別の種類の続き・30 秒経過・Lease の失効・セッションの変化で続きは `0x30` | FR-24, SEC-02 |
| UT-152 | discoverableCredentialsCanBeDeleted | 削除、再度の削除・non-discoverable は `0x2E`、別 RP のトークンは `0x33` | FR-24, FR-08 |
| UT-153 | userInformationCanBeUpdated | name の更新と displayName の削除、user.id の不一致 `0x02`、user の欠落 `0x14` | FR-24 |
| UT-154 | everyOperationIsAuthorizedByTheGateWithoutConsumption | 認証付きのサブコマンドごとに `CREDENTIAL_MANAGEMENT` の認可を求め、消費しない。続きは認可を求めない。拒否で `0x27` | FR-24, FR-13 |
| UT-155 | enumeratingWithNoCredentialsReturnsNoCredentials | credential がなければ RP の列挙は `0x2E`、件数は 0 | FR-24 |

### 1.16 高水準のクライアントとの照合 (`InteropServer`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-156 | serve | 環境変数 `TCSKE_INTEROP_PORT` 指定時のみ、実際の `AuthorizationGate` (ワンタイム ON。消費後に自動で再開) を使う認証器を TCP で公開する。終了時に「UP を伴う登録・認証の成功回数 = ワンタイムの消費回数」を確認する (CT-07) | FR-13, FR-21〜24 |

### 1.17 clientPIN (`ClientPinTest`)

| ID | テスト | 確認内容 | 要件 |
|---|---|---|---|
| UT-157 | setPinIsReportedInGetInfoAndCannotBeSetTwice | Protocol 1 / 2 で PIN を設定し clientPin が true、残り 8 回。受付ゲート (`CLIENT_PIN`) を経てワンタイムは消費しない。再度の設定は `0x33` | FR-25, FR-13 |
| UT-158 | newPinsAreValidated | 3 文字・64 バイト・不正な UTF-8 は `0x37`、パディング長の不正 `0x02`、認証値の不一致 `0x33`、欠落 `0x14`。4 コードポイント (12 バイト) は可 | FR-25, SEC-10 |
| UT-159 | pinTokensAuthorizeOperations | 未設定で `0x35`。getPinToken (Protocol 1 / 2、mc・ga) で登録 (UV フラグ)、permissions 付きの getPinToken は `0x02`。0x09 の cm トークンで資格情報の管理、permissions 0 は `0x02`、lbw は `0x40` | FR-25, FR-22, FR-24 |
| UT-160 | threeConsecutiveMismatchesRequireAPowerCycle | 誤り 1・2 回目 `0x31`、3 回目 `0x34`。以後は正しい PIN でも `0x34` で回数を減らさない。セッションの変化で解除、正しい PIN で 8 回に戻る | FR-25, SEC-02 |
| UT-161 | eightMismatchesBlockThePinUntilReset | 8 回の誤りで `0x32`、以後はトークン・変更とも `0x32`。Reset で PIN が消え、再設定できる | FR-25, FR-10 |
| UT-162 | changePinReplacesThePinAndRevokesTokens | 未設定 `0x35`、認証値の不一致 `0x33`、現在の PIN の誤り `0x31`、新しい PIN の違反 `0x37`。変更後は旧 PIN が `0x31`、発行済みのトークンは使えない | FR-25 |
| UT-163 | zeroLengthProbeReportsPinInvalidOncePinIsSet | 長さ 0 の pinUvAuthParam は PIN 未設定で `0x35`、設定済みで `0x31` | FR-25 |
| UT-164 | pinChecksRequireTheGateAndDoNotSpendRetriesWhenDenied | 受付ゲートの拒否 (`0x27`) では PIN を照合せず、試行回数を減らさない | FR-25, SEC-02, SEC-04 |
| UT-165 | builtInUvStillWorksWithAPinSet | PIN 設定後も内蔵 UV のトークン・`uv` オプションで登録できる | FR-22, FR-25 |
| UT-166 | pinStoreIsSharedAcrossTransports | 2 つの認証器 (トランスポート) で PIN の状態と試行回数を共有する | FR-25 |
| UT-167 | unreadablePinStorageIsTreatedAsSetAndRejectsPinOperations | 読み込めない PIN は clientPin true、PIN の操作は `0x7F`、長さ 0 のプローブは `0x31` | FR-25, SEC-10 |

## 2. CTAP 結合試験 (CT)

`scripts/test/fido2_nfc_test.py` (python-fido2 + PC/SC) を ENV-01 / ENV-02 で実行する。

| ID | 手順 | 期待結果 | 要件 |
|---|---|---|---|
| CT-01 | 本人確認後にリーダーへ載せ `--info` を実行 | versions `['FIDO_2_0', 'FIDO_2_1']`、AAGUID、options、extensions、pinUvAuthProtocols が表示される | FR-01, FR-06 |
| CT-02 | 引数なしで実行 (登録 → 再度本人確認 → 認証) | MakeCredential のフラグに UP・UV・AT、GetAssertion の署名検証 OK、counter ≥ 1 | FR-04, FR-05 |
| CT-03 | アテステーションを「自己アテステーション」にして CT-02 | fmt = packed、`PackedAttestation` による署名検証 OK (検証できなければスクリプトは終了コード 1) | FR-16 |
| CT-04 | 本人確認せずに `--info` | デバイスが見つからない (SELECT 拒否)、端末に本人確認ダイアログ | FR-15, SEC-04 |
| CT-05 | 実機なし: `TCSKE_INTEROP_OUT=… ./gradlew :fido-core:test --tests '*InteropVectorExport*' --rerun` → `python3 scripts/test/verify_interop_vectors.py …` | python-fido2 が GetInfo を解析し、packed 自己アテステーション (SELF) とアサーションの署名を検証できる。PIN/UV Auth Protocol 1 / 2 について、`PinProtocolV1` / `PinProtocolV2` で導出した共有鍵で認証器の暗号文を復号でき、HMAC が一致する。hmac-secret について、登録の拡張出力、ED フラグ付きのアサーションの署名、復号した 2 つの出力が `HMAC(CredRandom, salt)` に一致する (2026-11-05、python-fido2 2.0.0 で確認済み) | FR-04〜06, FR-16, FR-21 |
| CT-06 | 本人確認後に `--hmac-secret` を実行 (登録 → 認証 → hmac-secret の認証 2 回。ワンタイム ON の場合は都度本人確認) | 登録の拡張出力が `{"hmac-secret": true}`、SC-02 にチップ「hmac-secret (PRF)」。認証で 64 バイトの出力を復号でき、2 回の認証で同じ値 | FR-21 |
| CT-07 | 実機なし: `TCSKE_INTEROP_PORT=47777 ./gradlew :fido-core:test --tests '*InteropServer*' --rerun -i` → `python3 scripts/test/interop_client_e2e.py <host> 47777` (docs/TESTING.md §7.1) | python-fido2 の `Fido2Client` で UV 必須・パスキー・PRF・credProtect 3 の登録 (内蔵 UV の pinUvAuthToken)、PRF の出力が同じ salt で一致し異なる salt で異なる、`CredentialManagement` で件数・列挙・ユーザー情報の更新・削除。続けて clientPIN (PIN の設定、誤りと残り回数、PIN の cm トークン、PIN の変更、PIN を使う `Fido2Client` の登録・認証)。サーバの消費回数が UP を伴う登録・認証の回数 (6) と一致 (2026-11-05、python-fido2 2.0.0 で確認済み) | FR-13, FR-21〜25 |
| CT-08 | 本人確認後に `--client` を実行 (操作ごとに本人確認) | CT-07 の PIN 以外のシナリオが実機の NFC で成功する | FR-01, FR-21〜24 |
| CT-09 | PIN 未設定の状態で、本人確認後に `--pin` を実行 (操作ごとに本人確認) | CT-07 の clientPIN のシナリオが実機の NFC で成功する。終了後は SC-04 に「設定済み (残り 8 回)」。「PIN を消去」で未設定に戻る | FR-25, FR-26 |

python-fido2 は 2.0.0 を基準とする (`pip install "fido2[pcsc]==2.0.0"`)。試験スクリプトは低水準 API (`Ctap2`) を使い、
内蔵 UV を `options={"uv": True}` で直接指定する。高水準 API (`Fido2Client`) は CT-07 / CT-08 で確認する。

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
| IT-24 | NFC の切断と再接続 | 登録・認証の処理中に端末を離し、すぐに載せ直す (繰り返す) | 古い応答が新しい接続へ出ない。ログ "response discarded" が出る場合がある。異常終了しない | SEC-02 |
| IT-25 | 受付の停止 | 本人確認後に「停止」→ かざす | 反応しない (SELECT 拒否) | FR-11, SEC-02 |
| IT-26 | ワンタイムと同時要求 | ワンタイム ON。Bluetooth で本人確認待ち中に、NFC でかざして処理させる | 一方のみ成功し、他方は拒否 / 再度の本人確認待ち | FR-13 |
| IT-27 | Bluetooth の自動登録解除からの復帰 | Bluetooth ON で起動 → ホーム画面へ → 数分後にアプリへ戻る | 「ホスト待ち」に戻る (登録し直される) | FR-02 |
| IT-28 | 本人確認待ち中の Bluetooth 停止 | Bluetooth で本人確認待ちの間に Bluetooth を OFF にする | 画面が固まらない (ANR なし)。ホストには `0x2D` または応答なし | FR-02 |
| IT-29 | TalkBack | TalkBack を有効にして本人確認 → 受付中に他の項目を操作 | 「認証できます / 待機中」の変化のみ読み上げ、残り秒数は毎秒読み上げない | — (品質) |
| IT-30 | 文字サイズ・画面幅 | 文字サイズ 200%、ウィンドウを広い → 狭い → 広いに変更 | 文字が過大・縮小したままにならない | NFR-09 |
| IT-31 | タッチ確認用の登録 (F-04) | 各クライアントで登録・認証し、イベントログに想定外の MakeCredential (ダミー RP 等) が出ないか確認 | 出た場合は互換性マトリクスに記録 (ワンタイムが消費されるため) | FR-13 |
| IT-32 | メタデータを読み込めない場合 | `adb shell run-as net.tecogonaz.tcsecuritykeyemulator sh -c 'echo x > files/credentials.bin'` → アプリを再起動 | SC-02 に「読み込めません」と初期化ボタン。登録・認証は拒否。初期化後は登録できる | FR-09 |
| IT-33 | 言語設定 | SC-04「言語」→ OS の画面で English → 戻る → 日本語 → システムのデフォルト | 表示が切り替わり、説明行が選択に合う。受付中だった場合は受付が解除される | FR-19, NFR-07 |
| IT-34 | 注意書き | アプリのデータを消去して起動 → 戻る・外側タップ → [理解しました] → 再起動 | DL-03 は [理解しました] まで閉じない。再起動後は表示されない。SC-01・SC-04・SC-05 に注意書きのカードは表示されない | FR-20 |
| IT-35 | 利用規約・セキュリティポリシー | SC-05 →「利用規約」「セキュリティポリシー」、文書内のリンク (セキュリティポリシー、LICENSE、メール) を押す。英語表示でも確認 | 表示言語の版が開き、表・太字・リンクが崩れない。文書間のリンクはアプリ内、LICENSE は GitHub、メールはメールアプリで開く。英語表示では日本語版の項目も表示される | FR-20 |
| IT-36 | PIN の表示と消去 | CT-09 の後に SC-04「PIN」を確認 →「PIN を消去」(本人確認) → 再度 `--info` | 「設定済み (残り 8 回)」→ 消去後は「未設定」、clientPin が false。クレデンシャルは残る。本人確認を取り消すと消去しない | FR-26, SEC-09 |
| IT-37 | OS からの PIN の設定・変更 | Windows の「設定 → アカウント → サインイン オプション → セキュリティ キー → 管理」で PIN を追加・変更する (本人確認後にかざす) | PIN を設定・変更できる。誤った現在の PIN では変更できず、SC-04 の残り回数が減る | FR-25 |

## 4. 互換性マトリクス (CP)

試験結果を記録する。

試験結果を、クライアントの**版と API 層**を含めて記録する (同じライブラリでも API 層により結果が異なるため。F-03)。

| クライアント | 版 / API 層 | 接続 | 登録 | 認証 | パスキー | 備考 |
|---|---|---|---|---|---|---|
| Windows 11 / Edge | (版) / WebAuthn (webauthn.dll) | NFC (RC-S300/P) | | | | |
| Windows 11 / Chrome | (版) / WebAuthn (webauthn.dll) | NFC (RC-S300/P) | | | | |
| Windows 11 / python-fido2 | 2.0.0 / `Ctap2` (低水準) | NFC (RC-S300/P) | | | | 試験スクリプト |
| Windows 11 / python-fido2 | 2.0.0 / `Fido2Client` (高水準) | NFC (RC-S300/P) | | | | CT-08。実機なしでは成功 (CT-07、注 1) |
| macOS 27 / python-fido2 | 2.0.0 / `Ctap2` (低水準) | NFC (RC-S300/P) | | | | 試験スクリプト |
| macOS 27 / Safari | (版) | NFC (RC-S300/P) | | | | |
| macOS 27 / Chrome | (版) | NFC (RC-S300/P) | — | — | — | 非対応の想定 |
| Android 15+ / Chrome | (版) / Google Play 開発者サービス | NFC (端末同士) | | | | |
| libfido2 (`fido2-token` 等) | (版) | NFC (PC/SC) | | | | GET RESPONSE に `80 C0` を使う (1.1 で対応) |
| Windows 11 / Edge・Chrome | (版) | Bluetooth HID | | | | 実験的 |
| macOS 27 / Safari・Chrome | (版) | Bluetooth HID | | | | 実験的。libfido2 系は USB 以外の HID を列挙しない場合がある |

注 1: python-fido2 2.0.0 の `Fido2Client` は、内蔵 UV を使う前に PIN/UV プロトコルの選択を行う。CTAP 2.0 のみの版
(`pinUvAuthProtocols` を広告しない) では `ValueError: No compatible PIN/UV protocols supported!` となっていた
(外部レビュー F-03 の再現結果)。CTAP 2.1 (pinUvAuthToken・Protocol 2 / 1) に対応した版では、内蔵 UV でトークンを得て
UV 必須の登録・認証が成功する (2026-11-05、CT-07)。

## 5. 要件とテストの対応

| 要件 | テスト |
|---|---|
| FR-01 | UT-25〜33, 43〜50, CT-01 |
| FR-02 | UT-34〜39, 51〜57, 68〜73, 80, IT-23, 27, 28 |
| FR-04 / FR-05 | UT-11, 13〜16, 24, 82, 83, 87〜103, CT-02, CT-05, IT-01〜05 |
| FR-06 | UT-10, 32, CT-01, CT-05 |
| FR-07〜FR-09 | UT-106, IT-01, 12, 13, 32 |
| FR-10 | UT-23, IT-14 |
| FR-11〜FR-15 | UT-17〜19, 26, 58〜67, 76, 85, 86, 90, 132, 135, 138, 154, 156, CT-04, CT-07, IT-06〜10, 25, 26, 31 |
| FR-16 | UT-12, 50, 104, CT-03, CT-05 |
| FR-17 / FR-18 | UT-19, 74, IT-17 |
| FR-19 / FR-20 | IT-33 / UT-108〜111, IT-34, IT-35 |
| FR-21 | UT-10, 107, 123〜131, 156, CT-05〜08 |
| FR-22 | UT-10, 132〜140, 156, CT-07, CT-08 |
| FR-23 | UT-10, 141〜146, 150, CT-07, CT-08 |
| FR-24 | UT-10, 147〜155, 159, CT-07, CT-08 |
| FR-25 | UT-10, 157〜167, CT-07, CT-09, IT-37 |
| FR-26 | CT-09, IT-36 |
| NFR-03 / 04 / 07 / 09 / 10 | IT-22 / IT-15 / IT-20 / IT-21, 30 / IT-19 |
| (品質: アクセシビリティ) | IT-29 |
| SEC-02〜SEC-04 | UT-17, 26, 64, 65, 75, 77〜79, 81, 85, 133, 135, 139, 151, IT-07, 08, 11, 16, 24, 25 |
| SEC-07 / SEC-09 / SEC-10 | IT-18 / IT-10, 12, 13, 36 / UT-05〜07, 09, 22, 36, 38, 40〜42, 48, 49, 54, 84, 92〜94, 116, 120, 121, 123, 128, 134, 136, 148, 158, 167 |
