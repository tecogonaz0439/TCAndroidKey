// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.ctap2

import net.tecogonaz.tcandroidkey.fido.cbor.Cbor
import net.tecogonaz.tcandroidkey.fido.testutil.FakePolicy
import net.tecogonaz.tcandroidkey.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcandroidkey.fido.testutil.TestCrypto
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * 外部の検証器 (python-fido2) と照合するための応答ベクタを出力する。
 * 環境変数 TCAK_INTEROP_OUT に出力先を指定した場合のみ実行する (scripts/test/verify_interop_vectors.py で検証)。
 */
class InteropVectorExport {
    @Test
    fun exportVectors() {
        val out = System.getenv("TCAK_INTEROP_OUT")
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
                    2L to linkedMapOf("id" to "tcandroidkey.test", "name" to "test"),
                    3L to linkedMapOf("id" to byteArrayOf(1, 2, 3), "name" to "tester", "displayName" to "Tester"),
                    4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
                    7L to linkedMapOf("rk" to true, "uv" to true)
                )
            )
        )
        val cdh2 = TestCrypto.sha256("login".toByteArray())
        val ga = auth.process(
            byteArrayOf(CtapCommand.GET_ASSERTION.toByte()) + Cbor.encode(
                linkedMapOf<Long, Any?>(1L to "tcandroidkey.test", 2L to cdh2, 5L to linkedMapOf("uv" to true))
            )
        )
        val info = auth.process(byteArrayOf(CtapCommand.GET_INFO.toByte()))
        File(out!!).writeText(
            """{"makeCredential":"${Hex.encode(mc)}","cdh1":"${Hex.encode(cdh1)}",""" +
                """"getAssertion":"${Hex.encode(ga)}","cdh2":"${Hex.encode(cdh2)}","getInfo":"${Hex.encode(info)}"}"""
        )
    }
}
