# AP-B 参照仕様

| 区分 | 文書 | 参照箇所 |
|---|---|---|
| FIDO | FIDO Alliance, *Client to Authenticator Protocol (CTAP)* 2.0 / 2.1 — https://fidoalliance.org/specifications/ | コマンド (CTAP 2.1 §6)、ステータスコード (§8)、CTAPHID (§11.2)、NFC (§11.3) |
| W3C | *Web Authentication: An API for accessing Public Key Credentials* Level 2 / Level 3 — https://www.w3.org/TR/webauthn/ | authenticatorData、アテステーション形式 (packed / none)、フラグ |
| IETF | RFC 8949 *Concise Binary Object Representation (CBOR)* | CBOR エンコーディング |
| IETF | RFC 9052 / RFC 9053 *CBOR Object Signing and Encryption (COSE)* | COSE_Key、アルゴリズム識別子 (ES256 = -7) |
| ISO/IEC | ISO/IEC 7816-4 | APDU、ステータスワード、チェイニング |
| ISO/IEC | ISO/IEC 14443-4 | 近接型 IC カードの伝送プロトコル (HCE の下位層) |
| FIDO | FIDO HID 仕様 (CTAP 2.1 §11.2.8) | HID レポートディスクリプタ (Usage Page 0xF1D0) |
| Android | Host-based card emulation overview — https://developer.android.com/develop/connectivity/nfc/hce | HostApduService、AID 登録、優先サービス |
| Android | Android Keystore system — https://developer.android.com/privacy-and-security/keystore | 鍵生成、ユーザー認証、StrongBox、KeyInfo |
| Android | BiometricPrompt (`android.hardware.biometrics`) — https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt | 本人確認 |
| Android | BluetoothHidDevice — https://developer.android.com/reference/android/bluetooth/BluetoothHidDevice | HID Device プロファイル |
| 参考 | TCSameuraDamMonitor-android — https://github.com/tecogonaz0439/TCSameuraDamMonitor-android | UI 部品・ビルド構成の流用元 |
| 試験 | python-fido2 (Yubico) — https://github.com/Yubico/python-fido2 | CTAP 結合試験 |
