#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
TCAndroidKey の動作確認用スクリプト (PC/SC NFC リーダー経由)。

Windows 11 / macOS + Sony RC-S300 などの PC/SC リーダーで、ブラウザを介さずに
CTAP2 の GetInfo → MakeCredential → GetAssertion を実行し、署名を検証する。

準備:
    python3 -m pip install "fido2[pcsc]"

使い方:
    1. Android 端末で TCAndroidKey を開き「本人確認して開始」を実行する
       (設定「本人確認 1 回につき認証 1 回」が ON の場合は、登録と認証の間で再度本人確認する)
    2. 端末をリーダーに載せた状態で実行する
         python3 scripts/test/fido2_nfc_test.py            # 全ステップ
         python3 scripts/test/fido2_nfc_test.py --info     # GetInfo のみ
"""
import argparse
import hashlib
import os
import sys
import time

try:
    from fido2.ctap2 import Ctap2
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    sys.exit('python-fido2 が必要です: python3 -m pip install "fido2[pcsc]"')

RP_ID = "tcandroidkey.test"


def find_device(timeout):
    deadline = time.time() + timeout
    while True:
        devices = list(CtapPcscDevice.list_devices())
        if devices:
            return devices[0]
        if time.time() > deadline:
            sys.exit("FIDO デバイス (NFC) が見つかりません。アプリで本人確認後、端末をリーダーに載せてください。")
        time.sleep(0.5)


def wait_rearm(dev, prompt):
    input(f"\n{prompt}\n準備ができたら Enter (端末はリーダーから一度離して載せ直す) > ")
    return find_device(30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--info", action="store_true", help="GetInfo のみ実行")
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()

    dev = find_device(args.timeout)
    print(f"device: {dev}")
    ctap = Ctap2(dev)
    info = ctap.info
    print(f"versions : {info.versions}")
    print(f"aaguid   : {info.aaguid}")
    print(f"options  : {info.options}")
    print(f"transports: {getattr(info, 'transports', None)}")
    if args.info:
        return

    # --- 登録 (discoverable credential) ---
    cdh = hashlib.sha256(b"register-" + os.urandom(16)).digest()
    user_id = os.urandom(16)
    att = ctap.make_credential(
        cdh,
        {"id": RP_ID, "name": "TCAndroidKey test"},
        {"id": user_id, "name": "tester@example.com", "displayName": "Tester"},
        [{"type": "public-key", "alg": -7}],
        options={"rk": True, "uv": True},
    )
    cred = att.auth_data.credential_data
    print(f"\n[MakeCredential] fmt={att.fmt} flags=0x{att.auth_data.flags:02x} "
          f"credId={cred.credential_id.hex()[:16]}…")
    if att.fmt == "packed" and hasattr(att, "verify"):
        att.verify(cdh)
        print("  self attestation signature: OK")

    dev = wait_rearm(dev, "ワンタイム設定が ON の場合は、アプリで再度「本人確認して開始」を実行してください。")
    ctap = Ctap2(dev)

    # --- 認証 (allowList なし = パスキーとして検出) ---
    cdh2 = hashlib.sha256(b"login-" + os.urandom(16)).digest()
    assertion = ctap.get_assertion(RP_ID, cdh2, options={"uv": True})
    assertion.verify(cdh2, cred.public_key)
    print(f"\n[GetAssertion] flags=0x{assertion.auth_data.flags:02x} "
          f"counter={assertion.auth_data.counter} user={assertion.user}")
    print("  assertion signature: OK")
    print("\nすべて成功しました。アプリの「クレデンシャル」画面でテスト用の鍵を削除できます。")


if __name__ == "__main__":
    main()
