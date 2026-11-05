#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
fido-core が生成した CTAP2 応答 (InteropVectorExport) を python-fido2 で解析・検証する (実機不要)。

    TCSKE_INTEROP_OUT=/tmp/vectors.json ./gradlew :fido-core:test --tests '*InteropVectorExport*' --rerun
    python3 scripts/test/verify_interop_vectors.py /tmp/vectors.json
"""
import hashlib
import hmac
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
    print(f"GetInfo: versions={info.versions} extensions={info.extensions} pinUvAuthProtocols={info.pin_uv_protocols} options={info.options} aaguid={info.aaguid}")

    att = AttestationResponse.from_dict(parse(v["makeCredential"]))
    result = PackedAttestation().verify(att.att_stmt, att.auth_data, bytes.fromhex(v["cdh1"]))
    print(f"MakeCredential: fmt={att.fmt} type={result.attestation_type.name} flags=0x{att.auth_data.flags:02x}")

    asr = AssertionResponse.from_dict(parse(v["getAssertion"]))
    asr.verify(bytes.fromhex(v["cdh2"]), att.auth_data.credential_data.public_key)
    print(f"GetAssertion: signature OK, flags=0x{asr.auth_data.flags:02x} counter={asr.auth_data.counter} user={asr.user}")

    for p in v.get("pinProtocols", []):
        verify_pin_protocol(p)
    if "hmacSecret" in v:
        verify_hmac_secret(v["hmacSecret"])
    print("OK")


def shared_secret(protocol, p):
    sk = ec.derive_private_key(int(p["platformPrivateKey"], 16), ec.SECP256R1())
    pk = ec.EllipticCurvePublicNumbers(
        int(p["authenticatorKeyX"], 16), int(p["authenticatorKeyY"], 16), ec.SECP256R1()
    ).public_key()
    return protocol.kdf(sk.exchange(ec.ECDH(), pk))


def verify_hmac_secret(h):
    """hmac-secret: 登録の拡張出力、認証の署名と ED フラグ、復号した出力が HMAC(CredRandom, salt) に一致すること。"""
    att = AttestationResponse.from_dict(parse(h["makeCredential"]))
    if att.auth_data.extensions != {"hmac-secret": True}:
        sys.exit(f"hmac-secret: unexpected makeCredential extensions {att.auth_data.extensions}")
    asr = AssertionResponse.from_dict(parse(h["getAssertion"]))
    asr.verify(bytes.fromhex(h["cdh"]), att.auth_data.credential_data.public_key)
    if not asr.auth_data.flags & 0x80:
        sys.exit("hmac-secret: ED flag is not set")
    protocol = PinProtocolV1()
    output = protocol.decrypt(shared_secret(protocol, h), asr.auth_data.extensions["hmac-secret"])
    cred_random = bytes.fromhex(h["credRandomWithUv"])
    salts = bytes.fromhex(h["salts"])
    expected = b"".join(hmac.new(cred_random, salts[i:i + 32], hashlib.sha256).digest() for i in (0, 32))
    if output != expected:
        sys.exit("hmac-secret: output mismatch")
    print(f"hmac-secret: extension, signature (flags=0x{asr.auth_data.flags:02x}) and 2 outputs OK")


def verify_pin_protocol(p):
    """認証器の暗号文と HMAC を、python-fido2 の PinProtocolV1 / V2 で導出した共有鍵で検証する。"""
    protocol = {1: PinProtocolV1, 2: PinProtocolV2}[p["version"]]()
    secret = shared_secret(protocol, p)
    plaintext = bytes.fromhex(p["plaintext"])
    if protocol.decrypt(secret, bytes.fromhex(p["ciphertext"])) != plaintext:
        sys.exit(f"PIN/UV protocol {p['version']}: decrypt mismatch")
    if protocol.authenticate(secret, bytes.fromhex(p["message"])) != bytes.fromhex(p["hmac"]):
        sys.exit(f"PIN/UV protocol {p['version']}: HMAC mismatch")
    # python-fido2 が暗号化したものを同じ鍵で復号できること (暗号化の往復)
    if protocol.decrypt(secret, protocol.encrypt(secret, plaintext)) != plaintext:
        sys.exit(f"PIN/UV protocol {p['version']}: round trip mismatch")
    print(f"PIN/UV Auth Protocol {p['version']}: shared secret, decrypt and HMAC OK")


if __name__ == "__main__":
    main()
