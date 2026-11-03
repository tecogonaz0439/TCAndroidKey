# ローカルビルド (macOS + Android Studio)

## 1. 準備

1. **Android Studio** (最新安定版) をインストールする。JDK は同梱の JBR (Java 21) を使う。
2. Android Studio の **Settings → Languages & Frameworks → Android SDK** で次をインストールする。
   - SDK Platforms: **Android API 37** (`compileSdk = 37`)
   - SDK Tools: Android SDK Build-Tools (最新)、Android SDK Platform-Tools
3. 端末側: 開発者オプション → USB デバッグ (またはワイヤレスデバッグ) を有効にする。

## 2. 取得とビルド

```bash
git clone https://github.com/tecogonaz0439/TCSecurityKeyEmulator.git
```

```bash
cd TCSecurityKeyEmulator
```

Android Studio で **Open** → `TCSecurityKeyEmulator` フォルダを開く (初回 Gradle 同期で `local.properties` に `sdk.dir` が自動設定される)。
実行構成 `app` を選び、接続した端末で **Run** する。

コマンドラインの場合 (`ANDROID_HOME` / `JAVA_HOME` 未設定時は Android Studio の既定パスを自動で使う):

```bash
scripts/cicd/build-apk.sh
```

```bash
scripts/cicd/install-android.sh
```

単体テスト・lint・ビルドを一括で実行:

```bash
scripts/cicd/verify.sh
```

## 3. 補足

- クラウドとローカルは同じ `app/debug.keystore` で署名されるため、どちらでビルドした APK でも上書きインストールできる。
- バージョンは TCSameuraDamMonitor-android と揃えている (`gradle/libs.versions.toml`)。
  AGP / Kotlin を更新する場合は両リポジトリで合わせると管理しやすい。
- Android Studio のデバッガで HCE サービスをデバッグする場合、ブレークポイントで止めると
  NFC 通信がタイムアウトする点に注意 (ログ `adb logcat -s TCSecurityKeyEmulator` の利用を推奨)。
