#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
# SPDX-License-Identifier: Apache-2.0
"""
fido-core が生成した CTAP2 応答 (InteropVectorExport) を python-fido2 で解析・検証する (実機不要)。

    TCAK_INTEROP_OUT=/tmp/vectors.json ./gradlew :fido-core:test --tests '*InteropVectorExport*' --rerun
    python3 scripts/test/verify_interop_vectors.py /tmp/vectors.json
"""
import json
import sys

from fido2.attestation import PackedAttestation
from fido2.ctap2 import AssertionResponse, AttestationResponse, Info
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
    print("OK")


if __name__ == "__main__":
    main()
