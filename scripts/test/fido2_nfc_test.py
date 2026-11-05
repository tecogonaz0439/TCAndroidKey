#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
セキュリティキーエミュレータ (TCSecurityKeyEmulator) の動作確認用スクリプト (PC/SC NFC リーダー経由)。

Windows 11 / macOS + Sony RC-S300 などの PC/SC リーダーで、ブラウザを介さずに
CTAP2 の GetInfo → MakeCredential → GetAssertion を実行し、署名を検証する。

準備 (動作確認の基準版は python-fido2 2.0.0):
    python3 -m pip install "fido2[pcsc]==2.0.0"

検証内容:
    - fmt "packed" (自己アテステーション) の場合は署名を暗号学的に検証する。検証できなければ失敗 (終了コード 1)
    - fmt "none" の場合は attStmt が空であることを確認する (署名検証はない)
    - アサーションの署名を登録時の公開鍵で検証する

使い方:
    1. Android 端末でセキュリティキーエミュレータを開き「本人確認して開始」を実行する
       (設定「本人確認 1 回につき認証 1 回」が ON の場合は、登録と認証の間で再度本人確認する)
    2. 端末をリーダーに載せた状態で実行する
         python3 scripts/test/fido2_nfc_test.py            # 全ステップ
         python3 scripts/test/fido2_nfc_test.py --info     # GetInfo のみ
         python3 scripts/test/fido2_nfc_test.py --hmac-secret  # hmac-secret 拡張も確認する

--hmac-secret の確認内容 (DD-10 CT-06):
    - 登録の拡張出力が {"hmac-secret": true} であること
    - 認証で salt 2 つの出力 (各 32 バイト) を復号でき、2 回目の認証で同じ値になること
"""
import argparse
import hashlib
import os
import sys
import time

try:
    import fido2
    from fido2.attestation import PackedAttestation
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import PinProtocolV1
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    sys.exit('python-fido2 が必要です: python3 -m pip install "fido2[pcsc]==2.0.0"')

RP_ID = "tcsecuritykeyemulator.test"


def find_device(timeout):
    deadline = time.time() + timeout
    while True:
        devices = list(CtapPcscDevice.list_devices())
        if devices:
            return devices[0]
        if time.time() > deadline:
            sys.exit("FIDO デバイス (NFC) が見つかりません。アプリで本人確認後、端末をリーダーに載せてください。")
        time.sleep(0.5)


def hmac_secret_input(ctap, salts):
    """clientPIN の getKeyAgreement で共有鍵を作り、hmac-secret の入力 (salt の暗号化と saltAuth) を作る。"""
    protocol = PinProtocolV1()
    resp = ctap.client_pin(protocol.VERSION, 0x02)
    key_agreement, secret = protocol.encapsulate(resp[1])
    salt_enc = protocol.encrypt(secret, salts)
    ext = {1: key_agreement, 2: salt_enc, 3: protocol.authenticate(secret, salt_enc), 4: protocol.VERSION}
    return {"hmac-secret": ext}, lambda value: protocol.decrypt(secret, value)


def assert_hmac_secret(ctap, cred, salts):
    cdh = hashlib.sha256(b"prf-" + os.urandom(16)).digest()
    extensions, decrypt = hmac_secret_input(ctap, salts)
    assertion = ctap.get_assertion(RP_ID, cdh, extensions=extensions, options={"uv": True})
    assertion.verify(cdh, cred.public_key)
    encrypted = (assertion.auth_data.extensions or {}).get("hmac-secret")
    if not encrypted:
        sys.exit(f"  hmac-secret: no output (flags=0x{assertion.auth_data.flags:02x})")
    output = decrypt(encrypted)
    if len(output) != 64:
        sys.exit(f"  hmac-secret: unexpected output length {len(output)}")
    print(f"\n[GetAssertion + hmac-secret] flags=0x{assertion.auth_data.flags:02x} "
          f"output1={output[:32].hex()[:16]}… output2={output[32:].hex()[:16]}…")
    return output


def wait_rearm(dev, prompt):
    input(f"\n{prompt}\n準備ができたら Enter (端末はリーダーから一度離して載せ直す) > ")
    return find_device(30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--info", action="store_true", help="GetInfo のみ実行")
    ap.add_argument("--hmac-secret", action="store_true", help="hmac-secret 拡張の登録・認証も確認する")
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()

    print(f"python-fido2 {getattr(fido2, '__version__', '?')}")
    dev = find_device(args.timeout)
    print(f"device: {dev}")
    ctap = Ctap2(dev)
    info = ctap.info
    print(f"versions : {info.versions}")
    print(f"aaguid   : {info.aaguid}")
    print(f"options  : {info.options}")
    print(f"extensions: {info.extensions}")
    print(f"pinUvAuthProtocols: {info.pin_uv_protocols}")
    print(f"transports: {getattr(info, 'transports', None)}")
    if args.info:
        return

    # --- 登録 (discoverable credential) ---
    cdh = hashlib.sha256(b"register-" + os.urandom(16)).digest()
    user_id = os.urandom(16)
    att = ctap.make_credential(
        cdh,
        {"id": RP_ID, "name": "Security Key Emulator test"},
        {"id": user_id, "name": "tester@example.com", "displayName": "Tester"},
        [{"type": "public-key", "alg": -7}],
        extensions={"hmac-secret": True} if args.hmac_secret else None,
        options={"rk": True, "uv": True},
    )
    cred = att.auth_data.credential_data
    print(f"\n[MakeCredential] fmt={att.fmt} flags=0x{att.auth_data.flags:02x} "
          f"credId={cred.credential_id.hex()[:16]}…")
    if att.fmt == "packed":
        # 失敗時は例外 (InvalidSignature 等) で終了する。検証を省略して成功にしない。
        try:
            PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)
        except Exception as e:
            sys.exit(f"  self attestation signature: NG ({e!r})")
        print("  attestation: packed (self) — signature verified")
    elif att.fmt == "none":
        if att.att_stmt:
            sys.exit(f"  attestation: none but attStmt is not empty: {att.att_stmt!r}")
        print("  attestation: none — structure OK (no signature to verify)")
    else:
        sys.exit(f"  unexpected attestation format: {att.fmt}")
    if args.hmac_secret:
        if att.auth_data.extensions != {"hmac-secret": True}:
            sys.exit(f"  hmac-secret: unexpected registration output {att.auth_data.extensions!r}")
        print("  hmac-secret: enabled")

    dev = wait_rearm(dev, "ワンタイム設定が ON の場合は、アプリで再度「本人確認して開始」を実行してください。")
    ctap = Ctap2(dev)

    # --- 認証 (allowList なし = パスキーとして検出) ---
    cdh2 = hashlib.sha256(b"login-" + os.urandom(16)).digest()
    assertion = ctap.get_assertion(RP_ID, cdh2, options={"uv": True})
    assertion.verify(cdh2, cred.public_key)
    print(f"\n[GetAssertion] flags=0x{assertion.auth_data.flags:02x} "
          f"counter={assertion.auth_data.counter} user={assertion.user}")
    print("  assertion signature: OK")

    if args.hmac_secret:
        salts = hashlib.sha256(b"salt1").digest() + hashlib.sha256(b"salt2").digest()
        dev = wait_rearm(dev, "hmac-secret の 1 回目の認証を行います (ワンタイム ON の場合は再度本人確認)。")
        first = assert_hmac_secret(Ctap2(dev), cred, salts)
        dev = wait_rearm(dev, "hmac-secret の 2 回目の認証を行います (ワンタイム ON の場合は再度本人確認)。")
        second = assert_hmac_secret(Ctap2(dev), cred, salts)
        if first != second:
            sys.exit("  hmac-secret: outputs differ between assertions (must be deterministic)")
        print("  hmac-secret: outputs are deterministic — OK")
    print("\nすべて成功しました。アプリの「クレデンシャル」画面でテスト用の鍵を削除できます。")


if __name__ == "__main__":
    main()
