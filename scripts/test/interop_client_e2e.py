#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
python-fido2 の高水準 API (Fido2Client、ClientPin、CredentialManagement) で fido-core の認証器を操作する (実機不要。DD-10 CT-07)。

fido-core の InteropServer (JUnit) が TCP で認証器を公開し、このスクリプトが CTAPHID の CBOR メッセージとして中継する。

    TCSKE_INTEROP_PORT=47777 ./gradlew :fido-core:test --tests '*InteropServer*' --rerun -i   # 先に起動 (接続を待つ)
    python3 scripts/test/interop_client_e2e.py <host> 47777

同じシナリオ (run_scenario) を、実機の NFC でも fido2_nfc_test.py --client から実行する (DD-10 CT-08)。

確認内容:
    1. Fido2Client で UV 必須・パスキー必須・PRF・credProtect (UV 必須) の登録 (内蔵 UV の pinUvAuthToken を使う)
    2. Fido2Client で PRF 付きの認証を 2 回行い、同じ salt で同じ値、異なる salt で異なる値になること
    3. ClientPin.get_uv_token (cm 権限) と CredentialManagement による件数・RP・credential の列挙、ユーザー情報の更新、削除
    4. clientPIN: PIN の設定、誤った PIN と残り回数、PIN によるトークン (mc・ga / cm)、PIN の変更、PIN を求める Fido2Client の登録・認証
       (run_pin_scenario。PIN を設定するため最後に行う)
"""
import os
import socket
import struct
import sys

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapDevice, CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.hid import CAPABILITY, CTAPHID
from fido2.utils import sha256
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_ID = "tcsecuritykeyemulator.test"
ORIGIN = f"https://{RP_ID}"


class SocketDevice(CtapDevice):
    """InteropServer への TCP 接続を CTAPHID の CBOR デバイスとして見せる。"""

    def __init__(self, host, port):
        self._sock = socket.create_connection((host, port), timeout=30)

    @property
    def capabilities(self):
        return CAPABILITY.CBOR | CAPABILITY.NMSG

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)
        self._sock.sendall(struct.pack(">I", len(data)) + data)
        (length,) = struct.unpack(">I", self._recv(4))
        return self._recv(length)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise IOError("connection closed")
            buf += chunk
        return buf

    def close(self):
        try:
            self._sock.sendall(struct.pack(">I", 0))
        finally:
            self._sock.close()

    @classmethod
    def list_devices(cls):
        return iter(())


class NoPinInteraction(UserInteraction):
    """内蔵 UV のみを使う (PIN は求めない)。"""

    def request_pin(self, permissions, rp_id):
        sys.exit("unexpected PIN request: the PIN is not set")

    def request_uv(self, permissions, rp_id):
        return True


class PinOnlyInteraction(UserInteraction):
    """内蔵 UV を断り、PIN で UV する。"""

    def __init__(self, pin):
        self.pin = pin
        self.pin_requests = 0

    def request_pin(self, permissions, rp_id):
        self.pin_requests += 1
        return self.pin

    def request_uv(self, permissions, rp_id):
        return False


def prf_first(extension_results):
    prf = (extension_results or {}).get("prf") or {}
    first = (prf.get("results") or {}).get("first")
    if first is None:
        sys.exit(f"PRF: no result in {extension_results!r}")
    return bytes(first) if not isinstance(first, str) else first


def run_scenario(connect):
    """
    登録 → PRF 付きの認証 3 回 → 資格情報の管理 を行う。

    :param connect: connect(prompt) が CtapDevice を返す。実機では、ワンタイムの受付を使い切った後に
        利用者に再度の本人確認を求め、つなぎ直したデバイスを返す。
    """
    def new_client(prompt):
        return Fido2Client(connect(prompt), DefaultClientDataCollector(ORIGIN), NoPinInteraction())

    client = new_client("登録を行います。")
    info = client.info
    print(f"GetInfo: versions={info.versions} options={dict(info.options)} protocols={info.pin_uv_protocols}")

    # --- 1. 登録 (UV 必須・パスキー・PRF・credProtect 3) ---
    user_id = os.urandom(16)
    reg = client.make_credential(
        PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(name="E2E", id=RP_ID),
            user=PublicKeyCredentialUserEntity(name="e2e@example.com", id=user_id, display_name="E2E"),
            challenge=os.urandom(32),
            pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            extensions={
                "prf": {},
                "credentialProtectionPolicy": "userVerificationRequired",
                "enforceCredentialProtectionPolicy": True,
            },
        )
    )
    auth_data = reg.response.attestation_object.auth_data
    print(f"MakeCredential: flags=0x{auth_data.flags:02x} extensions={auth_data.extensions} "
          f"client extension results={dict(reg.client_extension_results)}")
    if not auth_data.is_user_verified():
        sys.exit("MakeCredential: UV flag is not set")
    if (auth_data.extensions or {}).get("credProtect") != 3:
        sys.exit("MakeCredential: credProtect 3 was not applied")
    if not (reg.client_extension_results.get("prf") or {}).get("enabled"):
        sys.exit("MakeCredential: PRF is not enabled")

    # --- 2. PRF 付きの認証 ---
    def assert_prf(salt, prompt):
        selection = new_client(prompt).get_assertion(
            PublicKeyCredentialRequestOptions(
                challenge=os.urandom(32),
                rp_id=RP_ID,
                user_verification=UserVerificationRequirement.REQUIRED,
                extensions={"prf": {"eval": {"first": salt}}},
            )
        )
        response = selection.get_response(0)
        if not response.response.authenticator_data.is_user_verified():
            sys.exit("GetAssertion: UV flag is not set")
        return prf_first(response.client_extension_results)

    salt_a = sha256(b"salt-a")
    first = assert_prf(salt_a, "PRF 付きの認証 (1/3) を行います。")
    second = assert_prf(salt_a, "PRF 付きの認証 (2/3) を行います。")
    other = assert_prf(sha256(b"salt-b"), "PRF 付きの認証 (3/3) を行います。")
    if first != second:
        sys.exit("PRF: outputs differ for the same salt")
    if first == other:
        sys.exit("PRF: outputs are equal for different salts")
    print("GetAssertion + PRF: same salt -> same output, different salt -> different output")

    # --- 3. 資格情報の管理 (内蔵 UV の cm トークン) ---
    ctap = Ctap2(connect("資格情報の管理を行います (ワンタイムは消費しません)。"))
    client_pin = ClientPin(ctap)
    token = client_pin.get_uv_token(ClientPin.PERMISSION.CREDENTIAL_MGMT)
    credman = CredentialManagement(ctap, client_pin.protocol, token)
    metadata = credman.get_metadata()
    print(f"CredentialManagement: protocol={client_pin.protocol.VERSION} metadata={dict(metadata)}")
    rps = credman.enumerate_rps()
    if [rp[CredentialManagement.RESULT.RP]["id"] for rp in rps] != [RP_ID]:
        sys.exit(f"enumerate_rps: unexpected {rps!r}")
    creds = credman.enumerate_creds(sha256(RP_ID.encode()))
    if len(creds) != 1 or creds[0][CredentialManagement.RESULT.CRED_PROTECT] != 3:
        sys.exit(f"enumerate_creds: unexpected {creds!r}")
    cred_id = creds[0][CredentialManagement.RESULT.CREDENTIAL_ID]
    descriptor = PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id["id"])
    credman.update_user_info(
        descriptor, PublicKeyCredentialUserEntity(name="renamed@example.com", id=user_id, display_name="Renamed")
    )
    creds = credman.enumerate_creds(sha256(RP_ID.encode()))
    if creds[0][CredentialManagement.RESULT.USER]["name"] != "renamed@example.com":
        sys.exit(f"update_user_info: not updated {creds!r}")
    credman.delete_cred(descriptor)
    if credman.get_metadata()[CredentialManagement.RESULT.EXISTING_CRED_COUNT] != 0:
        sys.exit("delete_cred: credential still exists")
    print("CredentialManagement: metadata, enumerate RPs / credentials, update user, delete OK")


def run_pin_scenario(connect, pin="1234", new_pin="56789"):
    """
    clientPIN を確認する。PIN を設定するため、認証器の PIN が未設定の状態で最後に実行する。
    実行後は new_pin が設定されたまま残る (実機ではアプリの設定画面の「PIN を消去」で消せる)。
    """
    ctap = Ctap2(connect("PIN を設定します (ワンタイムは消費しません)。"))
    if ctap.info.options.get("clientPin") is not False:
        sys.exit(f"clientPin must be false before the PIN scenario: {ctap.info.options}")
    client_pin = ClientPin(ctap)
    client_pin.set_pin(pin)
    if Ctap2(ctap.device).get_info().options.get("clientPin") is not True:
        sys.exit("clientPin is not true after setPIN")
    try:
        client_pin.get_pin_token("0000")
        sys.exit("a wrong PIN was accepted")
    except CtapError as e:
        if e.code != CtapError.ERR.PIN_INVALID:
            sys.exit(f"wrong PIN: unexpected error {e.code!r}")
    retries, _ = client_pin.get_pin_retries()
    if retries != 7:
        sys.exit(f"pinRetries after one mismatch: {retries}")
    token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    credman = CredentialManagement(ctap, client_pin.protocol, token)
    print(f"clientPIN: setPIN, wrong PIN (retries 7), PIN token with cm -> metadata {dict(credman.get_metadata())}")
    if client_pin.get_pin_retries()[0] != 8:
        sys.exit("pinRetries was not reset by the correct PIN")
    client_pin.change_pin(pin, new_pin)
    try:
        client_pin.get_pin_token(pin)
        sys.exit("the old PIN still works after changePIN")
    except CtapError:
        pass

    # PIN で UV する Fido2Client (内蔵 UV を断る)
    interaction = PinOnlyInteraction(new_pin)
    client = Fido2Client(connect("PIN による登録を行います。"), DefaultClientDataCollector(ORIGIN), interaction)
    reg = client.make_credential(
        PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(name="E2E", id=RP_ID),
            user=PublicKeyCredentialUserEntity(name="pin@example.com", id=os.urandom(16), display_name="PIN"),
            challenge=os.urandom(32),
            pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
    )
    if not reg.response.attestation_object.auth_data.is_user_verified():
        sys.exit("MakeCredential with PIN: UV flag is not set")
    client = Fido2Client(connect("PIN による認証を行います。"), DefaultClientDataCollector(ORIGIN), interaction)
    selection = client.get_assertion(
        PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32), rp_id=RP_ID, user_verification=UserVerificationRequirement.REQUIRED
        )
    )
    if not selection.get_response(0).response.authenticator_data.is_user_verified():
        sys.exit("GetAssertion with PIN: UV flag is not set")
    if interaction.pin_requests < 2:
        sys.exit(f"Fido2Client did not use the PIN ({interaction.pin_requests} requests)")
    print(f"clientPIN: changePIN, Fido2Client registration and assertion with the PIN ({interaction.pin_requests} PIN requests) OK")


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    dev = SocketDevice(host, port)
    try:
        # InteropServer はワンタイムの消費後に自動で受付を再開するため、同じ接続を使い続ける
        run_scenario(lambda prompt: dev)
        run_pin_scenario(lambda prompt: dev)
        print("OK")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
