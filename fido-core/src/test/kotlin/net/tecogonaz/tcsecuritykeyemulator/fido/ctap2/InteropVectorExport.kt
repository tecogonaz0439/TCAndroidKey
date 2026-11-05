// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.pin.PinUvAuthProtocol
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestPlatform
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * 外部の検証器 (python-fido2) と照合するための応答ベクタを出力する。
 * 環境変数 TCSKE_INTEROP_OUT に出力先を指定した場合のみ実行する (scripts/test/verify_interop_vectors.py で検証)。
 */
class InteropVectorExport {
    @Test
    fun exportVectors() {
        val out = System.getenv("TCSKE_INTEROP_OUT")
        assumeTrue(out != null)
        val auth = Ctap2Authenticator(
            InMemoryCredentialStore(), FakePolicy(),
            { AuthenticatorConfig(Hex.decode("523283ca3c2c48b58bffa722f900e190"), attestationMode = AttestationMode.SELF) },
            "interop"
        )
        val cdh1 = TestCrypto.sha256("register".toByteArray())
        val mc = auth.process(
            byteArrayOf(CtapCommand.MAKE_CREDENTIAL.toByte()) + Cbor.encode(
                linkedMapOf<Long, Any?>(
                    1L to cdh1,
                    2L to linkedMapOf("id" to "tcsecuritykeyemulator.test", "name" to "test"),
                    3L to linkedMapOf("id" to byteArrayOf(1, 2, 3), "name" to "tester", "displayName" to "Tester"),
                    4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
                    7L to linkedMapOf("rk" to true, "uv" to true)
                )
            )
        )
        val cdh2 = TestCrypto.sha256("login".toByteArray())
        val ga = auth.process(
            byteArrayOf(CtapCommand.GET_ASSERTION.toByte()) + Cbor.encode(
                linkedMapOf<Long, Any?>(1L to "tcsecuritykeyemulator.test", 2L to cdh2, 5L to linkedMapOf("uv" to true))
            )
        )
        val info = auth.process(byteArrayOf(CtapCommand.GET_INFO.toByte()))
        val vectors = linkedMapOf<String, Any>(
            "makeCredential" to Hex.encode(mc),
            "cdh1" to Hex.encode(cdh1),
            "getAssertion" to Hex.encode(ga),
            "cdh2" to Hex.encode(cdh2),
            "getInfo" to Hex.encode(info),
            "pinProtocols" to listOf(1L, 2L).map { pinProtocolVector(it) },
            "hmacSecret" to hmacSecretVector()
        )
        File(out!!).writeText(toJson(vectors))
    }

    /**
     * PIN/UV Auth Protocol の照合用ベクタ。テスト用のプラットフォーム鍵の秘密スカラーを出力し、
     * 外部検証器が同じ共有鍵を導出して、認証器の暗号文と HMAC を検証できるようにする。
     */
    private fun pinProtocolVector(version: Long): Map<String, Any> {
        val protocol = PinUvAuthProtocol.create(version)!!
        val platform = TestPlatform(version.toInt())
        val secret = protocol.decapsulate(platform.keyAgreement)
        val authKey = protocol.getPublicKey()
        val plaintext = ByteArray(64) { (it * 7).toByte() }
        val message = TestCrypto.sha256("pin-uv-auth".toByteArray())
        return linkedMapOf(
            "version" to version,
            "platformPrivateKey" to Hex.encode(platform.privateScalar),
            "authenticatorKeyX" to Hex.encode(authKey[-2L] as ByteArray),
            "authenticatorKeyY" to Hex.encode(authKey[-3L] as ByteArray),
            "plaintext" to Hex.encode(plaintext),
            "ciphertext" to Hex.encode(protocol.encrypt(secret, plaintext)),
            "message" to Hex.encode(message),
            "hmac" to Hex.encode(protocol.authenticate(secret, message))
        )
    }

    /**
     * hmac-secret の往復 (登録 → salt 2 つで認証)。外部検証器は共有鍵を導出して出力を復号し、
     * CredRandom (テスト用ストアから出力) と salt の HMAC に一致することを確認する。
     */
    private fun hmacSecretVector(): Map<String, Any> {
        val store = InMemoryCredentialStore()
        val auth = Ctap2Authenticator(
            store, FakePolicy(), { AuthenticatorConfig(Hex.decode("523283ca3c2c48b58bffa722f900e190")) }, "interop"
        )
        val cdh = TestCrypto.sha256("hmac-secret".toByteArray())
        val mc = auth.process(
            byteArrayOf(CtapCommand.MAKE_CREDENTIAL.toByte()) + Cbor.encode(
                linkedMapOf<Long, Any?>(
                    1L to cdh,
                    2L to linkedMapOf("id" to "tcsecuritykeyemulator.test"),
                    3L to linkedMapOf("id" to byteArrayOf(9), "name" to "prf"),
                    4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
                    6L to linkedMapOf("hmac-secret" to true),
                    7L to linkedMapOf("rk" to true)
                )
            )
        )
        val keyAgreementResp = auth.process(
            byteArrayOf(CtapCommand.CLIENT_PIN.toByte()) + Cbor.encode(linkedMapOf(1L to 1L, 2L to 2L))
        )
        val authKey = (Cbor.decode(keyAgreementResp, 1, keyAgreementResp.size - 1) as Map<*, *>)[1L] as Map<*, *>
        val platform = TestPlatform(1)
        val secret = platform.sharedSecret(authKey)
        val salts = TestCrypto.sha256("salt1".toByteArray()) + TestCrypto.sha256("salt2".toByteArray())
        val saltEnc = platform.encrypt(secret, salts)
        val ga = auth.process(
            byteArrayOf(CtapCommand.GET_ASSERTION.toByte()) + Cbor.encode(
                linkedMapOf<Long, Any?>(
                    1L to "tcsecuritykeyemulator.test",
                    2L to cdh,
                    4L to linkedMapOf(
                        "hmac-secret" to linkedMapOf(
                            1L to platform.keyAgreement, 2L to saltEnc, 3L to platform.authenticate(secret, saltEnc), 4L to 1L
                        )
                    ),
                    5L to linkedMapOf("uv" to true)
                )
            )
        )
        val (withUv, _) = store.credRandoms(store.list().single())!!
        return linkedMapOf(
            "makeCredential" to Hex.encode(mc),
            "getAssertion" to Hex.encode(ga),
            "cdh" to Hex.encode(cdh),
            "platformPrivateKey" to Hex.encode(platform.privateScalar),
            "authenticatorKeyX" to Hex.encode(authKey[-2L] as ByteArray),
            "authenticatorKeyY" to Hex.encode(authKey[-3L] as ByteArray),
            "salts" to Hex.encode(salts),
            "credRandomWithUv" to Hex.encode(withUv)
        )
    }

    /** 文字列・整数・リスト・マップのみの簡易 JSON 出力。 */
    private fun toJson(value: Any): String = when (value) {
        is String -> "\"$value\""
        is Long, is Int -> value.toString()
        is List<*> -> value.joinToString(",", "[", "]") { toJson(it!!) }
        is Map<*, *> -> value.entries.joinToString(",", "{", "}") { (k, v) -> "\"$k\":${toJson(v!!)}" }
        else -> error("unsupported JSON value: $value")
    }
}
