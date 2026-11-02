# TCAndroidKey

Android 端末を **FIDO2 (CTAP2) セキュリティキー** として振る舞わせる、**FIDO / FIDO2 Web アプリケーションのテスト用ツール**。
PC や他の Android 端末の NFC リーダーに端末をかざして、開発中の Web アプリの WebAuthn (パスキー / 2 要素認証) の登録・認証を試験できる。

> **注意: テスト用途専用です。YubiKey などの物理セキュリティキーの代替としては使用しないでください。**
> 本番サービスや重要なアカウントには登録しないでください。FIDO 認定は受けておらず、
> アンインストール等で鍵が失われても復旧できません。詳細は [設計書](docs/design/README.md) を参照。

- **NFC** (HCE によるカードエミュレーション) が主ターゲット。Bluetooth HID は実験的対応、USB は技術的に非対応
- 秘密鍵は **Android Keystore (StrongBox / TEE)** 内で生成し、端末外へ出さない。個別削除・全削除に対応
- **アプリ画面の表示中のみ**、かつ **指紋などで本人確認した直後のみ** 認証を受け付ける
- **Google Play 開発者サービス不要** (業務用端末にも導入可能)
- Android 15 以上 / Kotlin 2 / Jetpack Compose (Material 3)。UI は TCSameuraDamMonitor-android をベースにしている

## 使い方

1. 端末に画面ロックと指紋を設定し、NFC をオンにする
2. アプリを開いて「本人確認して開始」→ 指紋認証
3. 「認証できます (残り NN 秒)」の間に、端末の背面を NFC リーダーにかざす

## ドキュメント

| 文書 | 内容 |
|---|---|
| [docs/design/](docs/design/README.md) | 設計書一式 (基本設計・詳細設計・付録) |
| [docs/CLOUD-BUILD.md](docs/CLOUD-BUILD.md) | クラウド (Claude Code on the web) での APK ビルド環境の設定 |
| [docs/LOCAL-BUILD-macOS.md](docs/LOCAL-BUILD-macOS.md) | macOS + Android Studio でのローカルビルド |
| [docs/TESTING.md](docs/TESTING.md) | Windows / macOS / Android での動作確認手順 |

## リポジトリ構成

```
fido-core/   FIDO2 プロトコル実装 (CBOR, CTAP2, NFC APDU, CTAPHID)。純 Kotlin、単体テスト付き
app/         Android アプリ (Keystore, HCE サービス, Bluetooth HID, Compose UI)
scripts/
  cloud/     クラウド環境のセットアップスクリプト
  cicd/      build-apk.sh / verify.sh / install-android.sh
  test/      PC (PC/SC リーダー) からの動作確認スクリプト (python-fido2)
docs/        設計・手順書
```

## ビルド

```bash
scripts/cicd/build-apk.sh
```

出力: `build/cicd/apk/TCAndroidKey-debug.apk`

## ライセンス

Apache License 2.0 ([LICENSE](LICENSE))
