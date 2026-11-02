# AP-A 用語集

| 用語 | 説明 |
|---|---|
| AAGUID | Authenticator Attestation GUID。認証器のモデルを示す 16 バイトの識別子。本アプリは `523283ca-3c2c-48b5-8bff-a722f900e190` (MDS 未登録) |
| AID | Application Identifier。ISO 7816 でカード上のアプリケーションを識別する値。FIDO は `A0000006472F0001` |
| APDU | Application Protocol Data Unit。ISO 7816-4 のコマンド/応答の単位 |
| アテステーション (attestation) | 登録時に認証器が自身の種類・真正性を示す署名。本アプリは `none` または自己アテステーション (packed, x5c なし) |
| authenticatorData | 認証器が署名する構造体 (rpIdHash・フラグ・署名カウンタ・登録時は公開鍵) |
| BiometricPrompt | Android 標準の本人確認ダイアログ API |
| CBOR | Concise Binary Object Representation (RFC 8949)。CTAP2 のメッセージ形式 |
| Class 3 生体認証 (BIOMETRIC_STRONG) | Android の生体認証の強度区分のうち最も強いもの。Keystore 鍵の認証に使える |
| clientDataHash | クライアントデータ (チャレンジ・オリジン等) の SHA-256。署名対象に含まれる |
| clientPIN | CTAP の PIN によるユーザー検証機能。本アプリは非対応 |
| COSE_Key | CBOR Object Signing and Encryption (RFC 9052/9053) 形式の公開鍵 |
| CTAP | Client to Authenticator Protocol。クライアント (OS / ブラウザ) と認証器の通信規約。本アプリは CTAP 2.0 |
| CTAPHID | USB / HID 上の CTAP フレーミング。本アプリは Bluetooth HID で使用 |
| credential ID | クレデンシャルの識別子。本アプリは 32 バイトの乱数 |
| discoverable credential (パスキー) | 認証器にユーザー情報も保存され、ユーザー名なしで認証できるクレデンシャル (旧称 resident key, rk) |
| non-discoverable credential | RP が credential ID を保持し、allowList で指定して使うクレデンシャル |
| excludeList / excludeCredentials | 登録時に、既に登録済みの認証器での重複登録を防ぐための credential ID 一覧 |
| FIDO2 | WebAuthn と CTAP2 からなる FIDO Alliance の認証仕様の総称 |
| HCE | Host-based Card Emulation。Android アプリが NFC カードとして振る舞う機能 |
| Keystore (Android Keystore) | Android の鍵保管機構。鍵を TEE / StrongBox 内で生成・使用し、取り出せないようにする |
| MDS | FIDO Metadata Service。認定された認証器のメタデータを提供するサービス |
| PC/SC | PC とスマートカードリーダーの標準インターフェース |
| RP (Relying Party) | WebAuthn を利用して認証を行う Web アプリケーション |
| RP ID | RP の識別子 (通常はドメイン名) |
| StrongBox | 専用のセキュアエレメント (耐タンパ性ハードウェア) による Keystore 実装 |
| TEE | Trusted Execution Environment。メイン OS と分離された安全な実行環境 |
| UP (User Presence) | ユーザーが認証器の操作 (タッチ・タップ) をしたこと。本アプリではかざす操作 + 受付状態 |
| UV (User Verification) | ユーザー本人であることの確認 (生体認証・PIN 等)。本アプリでは BiometricPrompt |
| 受付状態 / 受付時間 | 本アプリ独自の概念。本人確認後に認証を受け付ける状態とその時間 |
| ワンタイム | 本アプリ独自の設定。1 回の本人確認で 1 回の登録/認証のみ許可する |
| WebAuthn | Web Authentication API (W3C)。ブラウザから公開鍵認証を使うための API |
