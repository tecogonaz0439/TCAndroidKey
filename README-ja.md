[English version](README.md)

# セキュリティキーエミュレータ

**セキュリティキーエミュレータ** (Security Key Emulator、プロジェクト名: TCSecurityKeyEmulator) は、Android 端末を **FIDO2 (CTAP 2.0 / 2.1) セキュリティキー** として動作させ、**FIDO / FIDO2 (WebAuthn) を使用する Web アプリケーションを試験する**ための Android アプリです。PC に接続した NFC リーダー (または別の Android 端末) に端末をかざして、開発中の Web アプリケーションのパスキー・セキュリティキーの登録とサインインを試せます。

> [!IMPORTANT]
> **本アプリはテスト用ツールです。YubiKey などの物理セキュリティキーの代替として使用しないでください。**
> 登録はテスト用のアカウント・環境に限り、本番サービスや重要なアカウントには登録しないでください。
> 本アプリは FIDO 認定を受けておらず、鍵のバックアップ・復旧もできません (アプリをアンインストールすると鍵は削除されます)。
> [利用規約](docs/TERMS-ja.md) と [セキュリティポリシー](docs/SECURITY-ja.md) を参照してください。

**本アプリは、FIDO Alliance、Yubico、Google その他の第三者が提供、承認、推奨するアプリではありません。**

## 機能

- **NFC による FIDO2 セキュリティキー** — ホストカードエミュレーション (HCE) で FIDO アプレットとして動作。CTAP 2.0 / 2.1 の MakeCredential、GetAssertion、GetNextAssertion、GetInfo、ClientPIN (鍵交換と内蔵 UV によるトークンの発行)、CredentialManagement、Selection、Reset (任意) に対応
- **パスキーと非検出クレデンシャル** — ES256 (ECDSA P-256)、1 サイトに複数アカウント、アテステーションは `none` または packed の自己アテステーション
- **内蔵 UV による CTAP 2.1** — クライアントは端末での本人確認で pinUvAuthToken を得る (PIN は不要)。credProtect の保護レベルと、クライアントからの資格情報の管理 (列挙・名前の変更・削除) に対応
- **hmac-secret 拡張** — WebAuthn の PRF 拡張の基盤となる CTAP の拡張。credential ごとの秘密値は Android Keystore の HMAC 鍵から導出
- **Android Keystore 内の鍵** — 登録ごとに StrongBox (または TEE) 内で秘密鍵を生成し、端末外へ出さない。個別削除・全削除に対応
- **許可したときだけ認証** — アプリの画面が表示されている間、指紋 (または画面ロック) による本人確認の直後の短い時間だけ、既定では本人確認 1 回につき 1 回だけ応答
- **イベントログ** — 登録・認証ごとの結果を表示 (メモリ内のみに保持)
- **Google Play 開発者サービス不要** — GMS を搭載しない業務用端末でも動作。インターネット接続の権限なし
- **Bluetooth HID (実験的)** — Bluetooth HID Device プロファイル上の CTAPHID
- **英語・日本語** — アプリ別の言語設定にも対応

USB には対応していません。Android のアプリは、root 化なしに USB HID デバイスとして動作できないためです。

## 動作環境

- Android 15 (API 35) 以上で、NFC とホストカードエミュレーションに対応した端末
- 画面ロック (Class 3 の生体認証 (指紋など) の登録を推奨)
- クライアント: 例として、PC/SC 対応の NFC リーダーを接続した Windows PC、または NFC 対応の別の Android 端末

## 入手方法

本アプリは、現時点でアプリストアや GitHub Releases での配布を行っていません。ソースコードから APK をビルドしてください。

```bash
scripts/cicd/build-apk.sh
```

APK は `build/cicd/apk/TCSecurityKeyEmulator-debug.apk` に出力されます。ビルド環境の準備は [クラウドでのビルド](docs/CLOUD-BUILD.md) または [macOS でのローカルビルド](docs/LOCAL-BUILD-macOS.md) を参照してください。

debug ビルドは、アプリを上書き更新できるよう (アンインストールすると鍵がすべて削除されるため)、本リポジトリで公開している共通の鍵で署名しています。同じ署名の APK は誰でも作成できるため、自分でビルドした APK、または開発者から直接入手した APK のみをインストールしてください。

## 使い方

1. 端末に画面ロックと指紋を設定し、NFC をオンにします。
2. アプリを開いて **本人確認して開始** を押し、指紋で本人確認します。
3. **認証できます** と表示されている間に、端末の背面を NFC リーダーにかざします。

Windows・macOS・Android での手順ごとの確認方法 ([python-fido2](https://github.com/Yubico/python-fido2) を使う Python スクリプトを含む) は [テスト手順](docs/TESTING.md) を参照してください。

## 互換性

| クライアント | 接続 | 状態 |
|---|---|---|
| Windows 11 (Edge / Chrome) | NFC (PC/SC リーダー) | 利用可の想定 (試験中) |
| python-fido2 2.0.0 (低水準 API `Ctap2`) | NFC (PC/SC リーダー) | 応答形式を検証済み |
| Android (Chrome) | NFC | 利用可の想定 (試験中) |
| macOS (Chrome) | NFC | ブラウザが非対応 |
| Windows / macOS のブラウザ | Bluetooth HID | 実験的 |

既知の制約 (clientPIN 非対応、CTAP 2.1 は一部のみ、U2F 非対応、largeBlob 非対応など) は [設計書](docs/design/appendix/C_roadmap.md) に記載しています。

## ドキュメント

| 文書 | 内容 |
|---|---|
| [設計書](docs/design/README.md) | 基本設計・詳細設計・付録 |
| [クラウドでのビルド](docs/CLOUD-BUILD.md) | クラウド環境での APK のビルド |
| [macOS でのローカルビルド](docs/LOCAL-BUILD-macOS.md) | macOS + Android Studio でのビルド |
| [テスト手順](docs/TESTING.md) | Windows・macOS・Android での動作確認 |

## リポジトリ

- **GitHub**: [tecogonaz0439/TCSecurityKeyEmulator](https://github.com/tecogonaz0439/TCSecurityKeyEmulator)

```
fido-core/   FIDO2 プロトコル実装 (CBOR、CTAP2、NFC APDU、CTAPHID、認可ゲート)。純 Kotlin、単体テスト付き
app/         Android アプリ (Keystore、HCE サービス、Bluetooth HID、Compose UI)
scripts/     クラウド環境のセットアップ、ビルド・検証・インストール、試験用スクリプト (python-fido2)
docs/        設計書、ビルド・テスト手順、利用規約、セキュリティポリシー
```

不具合の報告や Pull Request は、本リポジトリで受け付けています。脆弱性は、公開の Issue ではなく、[セキュリティポリシー](docs/SECURITY-ja.md) に記載の方法でメールにてご報告ください。

## リンク

- 利用規約: [日本語](docs/TERMS-ja.md) / [英語](docs/TERMS.md)
- セキュリティポリシー: [日本語](docs/SECURITY-ja.md) / [英語](SECURITY.md)

## ライセンス

ソースコードは [Apache License, Version 2.0](LICENSE) で公開しています。

本アプリの UI は [TCSameuraDamMonitor-android](https://github.com/tecogonaz0439/TCSameuraDamMonitor-android) をベースにしています。アプリのアイコンは [Material Symbols](https://github.com/google/material-design-icons) の「security_key」(Apache License 2.0) をもとにしています。
