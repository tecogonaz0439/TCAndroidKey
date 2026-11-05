// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.session.AuthorizationGate
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * 外部のクライアント (python-fido2 の高水準 API `Fido2Client` 等) から、TCP 経由で認証器を操作するための試験用サーバ。
 * 環境変数 TCSKE_INTEROP_PORT を指定した場合のみ実行する (scripts/test/interop_client_e2e.py。DD-10 CT-07)。
 *
 * 形式: 要求・応答とも「長さ (4 バイト、ビッグエンディアン) ‖ CTAP2 メッセージ」。長さ 0 の要求で終了する。
 *
 * 認可は実際の [AuthorizationGate] (前面表示・受付中・ワンタイム ON) を使う。ワンタイムが消費されたら、
 * 利用者の再度の本人確認に相当する arm を自動で行い、消費の回数を記録する。
 * 終了時に「UP を伴う登録・認証の成功 1 回につき消費 1 回」であることを確認する。
 */
class InteropServer {
    @Test
    fun serve() {
        val port = System.getenv("TCSKE_INTEROP_PORT")?.toIntOrNull()
        assumeTrue(port != null)
        var now = 0L
        var consumed = 0
        lateinit var gate: AuthorizationGate
        gate = AuthorizationGate(
            elapsed = { now },
            oneTime = { true },
            listener = object : AuthorizationGate.Listener {
                override fun onConsumed(rpId: String?) {
                    consumed++
                    gate.arm(ARM_MILLIS)
                }
            }
        )
        gate.setForeground(true)
        gate.arm(ARM_MILLIS)
        val policy = AuthorizationPolicy { request, keepAlive -> gate.authorize(request, keepAlive, blocking = false) }
        var userOperations = 0
        val authenticator = Ctap2Authenticator(
            InMemoryCredentialStore(), policy,
            { AuthenticatorConfig(Hex.decode("523283ca3c2c48b58bffa722f900e190"), transports = listOf("usb")) },
            "interop",
            listener = { e ->
                println("[interop] ${CtapCommand.name(e.command)} -> ${CtapStatus.name(e.status)}${e.detail?.let { " ($it)" } ?: ""}")
            },
            monotonicClock = { now }
        )
        ServerSocket().use { server ->
            server.soTimeout = ACCEPT_TIMEOUT_MS
            server.bind(InetSocketAddress("0.0.0.0", port!!))
            println("[interop] listening on port $port")
            server.accept().use { socket ->
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                while (true) {
                    val length = try {
                        input.readInt()
                    } catch (e: EOFException) {
                        break
                    }
                    if (length == 0) break
                    val request = ByteArray(length).also { input.readFully(it) }
                    now += STEP_MILLIS
                    val response = authenticator.process(request)
                    if (response[0].toInt() == 0 && withUserPresence(request)) userOperations++
                    output.writeInt(response.size)
                    output.write(response)
                    output.flush()
                }
            }
        }
        println("[interop] successful MakeCredential/GetAssertion with UP: $userOperations, one-time consumptions: $consumed")
        // ワンタイムは登録・認証の成功ごとに 1 回だけ消費する (トークンの発行・資格情報の管理・silent では消費しない)
        assertEquals(userOperations, consumed)
    }

    /** UP を伴う登録・認証か (GetAssertion の `up: false` を除く)。 */
    private fun withUserPresence(request: ByteArray): Boolean = when (request[0].toInt()) {
        CtapCommand.MAKE_CREDENTIAL -> true
        CtapCommand.GET_ASSERTION -> {
            val params = Cbor.decode(request, 1, request.size - 1) as Map<*, *>
            (params[5L] as? Map<*, *>)?.get("up") != false
        }
        else -> false
    }

    private companion object {
        const val ARM_MILLIS = 60_000L
        const val STEP_MILLIS = 10L
        const val ACCEPT_TIMEOUT_MS = 180_000
    }
}
