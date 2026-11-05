# 動作確認手順

動作確認はすべてローカルで行う。

| 環境 | 接続 | 主な確認方法 |
|---|---|---|
| Windows 11 + Sony RC-S300/P | NFC (PC/SC) | Windows のセキュリティキー設定、Edge/Chrome で webauthn.io、python-fido2 |
| macOS 27 + Sony RC-S300/P | NFC (PC/SC) | python-fido2 (主)、Safari で webauthn.io (参考) |
| Android 15+ (別端末、NFC 搭載) | NFC (端末同士) | Chrome で webauthn.io |
| Windows / macOS (実験的) | Bluetooth HID | Edge/Chrome で webauthn.io |

## 1. インストールと初期設定 (認証器となる Android 端末)

1. クラウドで作成した `TCSecurityKeyEmulator-debug.apk` を PC にダウンロードし、USB デバッグを有効にした端末へインストールする。

   ```bash
   adb install -r TCSecurityKeyEmulator-debug.apk
   ```

   (または `scripts/cicd/install-android.sh --apk <APK のパス>`)
2. 端末に **画面ロック** (PIN 等) と **指紋** を設定し、**NFC をオン** にする。
3. アプリを開き「本人確認して開始」→ 指紋認証 → 「認証できます / 残り NN 秒」になることを確認する。
4. ログ確認 (任意):

   ```bash
   adb logcat -s TCSecurityKeyEmulator
   ```

   logcat にはコマンド名と結果 (例 `authenticatorMakeCredential → CTAP2_OK`) のみを出力する。
   RP ID・ユーザー名はアプリの「ログ」画面で確認する。

> 注意: **アプリをアンインストールすると、登録した鍵はすべて削除される**。更新は上書きインストールで行う。
>
> 旧名 TCAndroidKey (パッケージ `net.tecogonaz.tcandroidkey`) をインストールしている場合は、アンインストールしてから
> 本アプリをインストールし、鍵を再登録する (別アプリのため上書きできない。同じ FIDO AID を登録したアプリが 2 つあると、
> リーダーにかざしたときにどちらが応答するかが不定になる)。

## 2. Windows 11 + RC-S300/P

1. Sony の「NFC ポートソフトウェア」(RC-S300 用 PC/SC ドライバー) をインストールし、リーダーを接続する。
2. **CTAP レベルの確認 (推奨・最初に実施)**

   ```bash
   py -m pip install "fido2[pcsc]==2.0.0"
   ```

   ```bash
   py scripts\test\fido2_nfc_test.py --info
   ```

   アプリで本人確認 → 端末をリーダーに載せる → `versions: ['FIDO_2_0', 'FIDO_2_1']` と AAGUID が表示されれば NFC 通信は正常。
   続けて `py scripts\test\fido2_nfc_test.py` で登録・認証・署名検証まで確認する。
3. **ブラウザでの確認**: Edge / Chrome で https://webauthn.io を開く。
   - Register: 「Advanced settings」で Authenticator Attachment = Cross-Platform、Discoverable Credential = Required (パスキー) または Discouraged、User Verification = Preferred
   - Windows のダイアログで「セキュリティキー」を選ぶ → アプリで本人確認 → 端末をリーダーにかざす
   - Authenticate も同様に実施し、成功することを確認する。
4. Windows の **設定 → アカウント → サインイン オプション → セキュリティ キー → 管理** でも認識を確認できる
   PIN の追加・変更もここから行える (DD-10 IT-37。本人確認後にかざす)。リセットは本アプリの設定「PC からのリセットを許可」が ON のときのみ有効。

## 3. macOS 27 + RC-S300/P

1. リーダーが PC/SC (CCID) として認識されているか確認する。

   ```bash
   system_profiler SPSmartCardsDataType
   ```

   リーダー名が表示されない場合、macOS 標準 CCID ドライバーが RC-S300 に未対応の可能性がある。
2. **CTAP レベルの確認 (主)**

   ```bash
   python3 -m pip install "fido2[pcsc]==2.0.0"
   ```

   ```bash
   python3 scripts/test/fido2_nfc_test.py
   ```

3. **ブラウザ (参考)**: macOS の Chrome は NFC (PC/SC) のセキュリティキーに対応していない。
   Safari はスマートカードリーダー経由の NFC セキュリティキーを扱える可能性があるため、webauthn.io で試して結果を記録する。

## 4. Android 15+ (別端末) をクライアントにする

1. クライアント端末の NFC をオンにし、Chrome で https://webauthn.io を開く。
2. Register → 「別のデバイスを使用 / セキュリティキー」を選ぶ。
3. 認証器端末でアプリを開いて本人確認し、**2 台の背面 (NFC アンテナ) を重ねて** 静止させる。
4. Authenticate も同様に確認する。

> NFC アンテナ位置は機種により異なる (多くは背面中央〜カメラ付近)。読み取りが不安定な場合は位置を少しずらす。

## 5. Bluetooth HID (実験的)

1. アプリの設定で「Bluetooth HID セキュリティキーとして使う」を ON → 権限を許可する。
2. メイン画面の Bluetooth 行で「開始」→「この端末を検出可能にする」。
3. PC の Bluetooth 設定から本端末を追加 (ペアリング) する。
4. ブラウザで webauthn.io → セキュリティキーを選択 → 端末に本人確認ダイアログが表示されるので指紋認証する。
5. 結果 (OS / ブラウザ毎に利用可否) を記録する。

## 6. 確認項目チェックリスト

| # | 項目 | 期待結果 |
|---|---|---|
| 1 | 本人確認前にかざす | 認証されない。端末に本人確認ダイアログが表示され、確認後に再度かざすと成功 |
| 2 | アプリをバックグラウンドにしてかざす | 認証されない (イベントログに "not in the foreground") |
| 3 | 受付時間の経過後にかざす | 認証されない |
| 4 | ワンタイム ON で連続 2 回認証 | 2 回目は本人確認が再度必要 |
| 5 | パスキー (discoverable) 登録 → ユーザー名なしでログイン | 成功し、ユーザーが選択される |
| 6 | 非 discoverable 登録 → ログイン | 成功 |
| 7 | 同じサイトで同じユーザーを再登録 | 既存の鍵が置き換わる (またはサイトの excludeList により拒否) |
| 8 | 同じ RP に複数アカウント登録 → ユーザー名なしログイン | アカウント選択が表示される |
| 9 | クレデンシャル画面で個別削除 | 本人確認後に削除され、そのサイトでログイン不可になる |
| 10 | すべて削除 | 本人確認後に全件削除される |
| 11 | StrongBox 搭載端末 | クレデンシャルに「StrongBox」と表示される |
| 12 | 画面ロックを解除 (無効化) | 鍵が使えなくなる / 新規登録不可の表示になる |
| 13 | PC からのリセット (設定 OFF / ON) | OFF: 拒否、ON: 全削除 |
| 14 | 処理中に端末を離してすぐ載せ直す (繰り返す) | 異常終了しない。古い応答が出ない (DD-10 IT-24) |
| 15 | 本人確認後に「停止」してからかざす | 認証されない |
| 16 | Bluetooth ON で起動 → ホームへ → 数分後に戻る | 「PC からの接続待ち」に戻る (DD-10 IT-27) |
| 17 | TalkBack を有効にして受付中に操作 | 残り秒数が毎秒読み上げられない |
| 18 | 設定 →「言語」で English / 日本語 / システムのデフォルトに切り替える | 表示が切り替わる (DD-10 IT-33) |
| 19 | アプリのデータを消去して起動 | 注意書きダイアログが表示され、「理解しました」まで閉じない。「このアプリについて」に注意書きがある (DD-10 IT-34) |
| 20 | `python3 scripts/test/fido2_nfc_test.py --hmac-secret` (PC/SC リーダー) | 登録で hmac-secret が有効になり、クレデンシャル画面に「hmac-secret (PRF)」。2 回の認証で同じ出力 (DD-10 CT-06) |
| 21 | `python3 scripts/test/fido2_nfc_test.py --client` (PC/SC リーダー。操作ごとに本人確認) | python-fido2 の `Fido2Client` で UV 必須・PRF・credProtect 3 の登録、PRF 付きの認証 3 回、資格情報の管理 (列挙・名前の変更・削除) が成功する (DD-10 CT-08) |
| 22 | Chrome の「セキュリティ キーの管理」(`chrome://settings/securityKeys`) の「ログイン データ」で、データの表示・削除 | パスキーが列挙され、削除できる (クライアントが内蔵 UV のトークンに対応する場合。結果を互換性マトリクスに記録) |
| 23 | PIN 未設定で `python3 scripts/test/fido2_nfc_test.py --pin` → 設定画面の「PIN」 | PIN の設定・変更、PIN による登録・認証が成功し、設定画面に「設定済み (残り 8 回)」(DD-10 CT-09) |
| 24 | 設定画面の「PIN を消去」 | 本人確認後に「未設定」になる。クレデンシャルは残る (DD-10 IT-36) |

## 7. 実機なしでの応答形式の確認 (python-fido2)

fido-core が生成した応答を python-fido2 (2.0.0) で解析・検証する (DD-10 CT-05)。

```bash
TCSKE_INTEROP_OUT=/tmp/tcske-vectors.json ./gradlew :fido-core:test --tests '*InteropVectorExport*' --rerun
```

```bash
python3 scripts/test/verify_interop_vectors.py /tmp/tcske-vectors.json
```

GetInfo の内容、packed 自己アテステーション (`type=SELF`) とアサーションの署名検証結果、
PIN/UV Auth Protocol 1 / 2 の照合結果 (`shared secret, decrypt and HMAC OK`) が表示され、最後に `OK` となる。

python-fido2 2.0.0 は Python 3.10 以上が必要である。macOS 標準の Python 3.9 しかない場合は、
ホストで wheel を取得し、コンテナ (Apple `container` 等) の Python 3.12 で実行できる。

```bash
python3 -m pip download "fido2==2.0.0" --python-version 3.12 --platform manylinux_2_34_aarch64 --platform manylinux2014_aarch64 --only-binary=:all: -d /tmp/tcske-wheels
```

```bash
container run --rm -v /tmp:/work -v "$PWD/scripts:/scripts:ro" docker.io/library/python:3.12-slim sh -c "pip install -q --no-index --find-links /work/tcske-wheels fido2==2.0.0 && python /scripts/test/verify_interop_vectors.py /work/tcske-vectors.json"
```

### 7.1 高水準のクライアント (Fido2Client) による確認

fido-core の認証器を TCP で公開し、python-fido2 の `Fido2Client`・`ClientPin`・`CredentialManagement` で操作する (DD-10 CT-07)。
先にサーバ (JUnit) を起動して接続を待たせ、別の端末でクライアントを実行する。

```bash
TCSKE_INTEROP_PORT=47777 ./gradlew :fido-core:test --tests '*InteropServer*' --rerun -i
```

```bash
python3 scripts/test/interop_client_e2e.py 127.0.0.1 47777
```

clientPIN のシナリオ (`run_pin_scenario`) も続けて実行する。コンテナで実行する場合は、ホストのアドレス (Apple `container` では既定で `192.168.64.1`) を指定する。
クライアントの出力の最後が `OK`、サーバのログに `one-time consumptions` が UP を伴う登録・認証の回数と一致して表示されれば成功。

