#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
fido-core が生成した CTAP2 応答 (InteropVectorExport) を python-fido2 で解析・検証する (実機不要)。

    TCSKE_INTEROP_OUT=/tmp/vectors.json ./gradlew :fido-core:test --tests '*InteropVectorExport*' --rerun
    python3 scripts/test/verify_interop_vectors.py /tmp/vectors.json
"""
import json
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.attestation import PackedAttestation
from fido2.ctap2 import AssertionResponse, AttestationResponse, Info
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2 import cbor


def parse(hex_resp):
    raw = bytes.fromhex(hex_resp)
    if raw[0] != 0:
        sys.exit(f"CTAP status 0x{raw[0]:02x}")
    return cbor.decode(raw[1:])


def main():
    v = json.load(open(sys.argv[1]))
    info = Info.from_dict(parse(v["getInfo"]))
    print(f"GetInfo: versions={info.versions} options={info.options} aaguid={info.aaguid}")

    att = AttestationResponse.from_dict(parse(v["makeCredential"]))
    result = PackedAttestation().verify(att.att_stmt, att.auth_data, bytes.fromhex(v["cdh1"]))
    print(f"MakeCredential: fmt={att.fmt} type={result.attestation_type.name} flags=0x{att.auth_data.flags:02x}")

    asr = AssertionResponse.from_dict(parse(v["getAssertion"]))
    asr.verify(bytes.fromhex(v["cdh2"]), att.auth_data.credential_data.public_key)
    print(f"GetAssertion: signature OK, flags=0x{asr.auth_data.flags:02x} counter={asr.auth_data.counter} user={asr.user}")

    for p in v.get("pinProtocols", []):
        verify_pin_protocol(p)
    print("OK")


def verify_pin_protocol(p):
    """認証器の暗号文と HMAC を、python-fido2 の PinProtocolV1 / V2 で導出した共有鍵で検証する。"""
    protocol = {1: PinProtocolV1, 2: PinProtocolV2}[p["version"]]()
    sk = ec.derive_private_key(int(p["platformPrivateKey"], 16), ec.SECP256R1())
    pk = ec.EllipticCurvePublicNumbers(
        int(p["authenticatorKeyX"], 16), int(p["authenticatorKeyY"], 16), ec.SECP256R1()
    ).public_key()
    shared_secret = protocol.kdf(sk.exchange(ec.ECDH(), pk))
    plaintext = bytes.fromhex(p["plaintext"])
    if protocol.decrypt(shared_secret, bytes.fromhex(p["ciphertext"])) != plaintext:
        sys.exit(f"PIN/UV protocol {p['version']}: decrypt mismatch")
    if protocol.authenticate(shared_secret, bytes.fromhex(p["message"])) != bytes.fromhex(p["hmac"]):
        sys.exit(f"PIN/UV protocol {p['version']}: HMAC mismatch")
    # python-fido2 が暗号化したものを同じ鍵で復号できること (暗号化の往復)
    if protocol.decrypt(shared_secret, protocol.encrypt(shared_secret, plaintext)) != plaintext:
        sys.exit(f"PIN/UV protocol {p['version']}: round trip mismatch")
    print(f"PIN/UV Auth Protocol {p['version']}: shared secret, decrypt and HMAC OK")


if __name__ == "__main__":
    main()
