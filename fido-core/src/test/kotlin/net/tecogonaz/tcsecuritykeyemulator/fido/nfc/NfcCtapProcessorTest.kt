// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.nfc

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.Cbor
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AttestationMode
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthenticatorConfig
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.FakePolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.InMemoryCredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.testutil.TestCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class NfcCtapProcessorTest {

    private val select = Hex.decode("00A4040008A0000006472F000100")

    private fun sw(resp: ByteArray): Int =
        ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)

    private fun body(resp: ByteArray): ByteArray = resp.copyOfRange(0, resp.size - 2)

    @Test
    fun selectReturnsVersion() {
        val p = NfcCtapProcessor({ _, _ -> byteArrayOf(0) })
        val r = p.process(select)
        assertEquals(0x9000, sw(r))
        assertEquals("FIDO_2_0", String(body(r)))
    }

    @Test
    fun selectIsRejectedWhenGateClosed() {
        val p = NfcCtapProcessor({ _, _ -> byteArrayOf(0) }, selectGate = { false })
        assertEquals(0x6A82, sw(p.process(select)))
        assertEquals(0x6A82, sw(p.process(Hex.decode("80100000010400"))))
    }

    @Test
    fun otherAidIsNotFound() {
        val p = NfcCtapProcessor({ _, _ -> byteArrayOf(0) })
        assertEquals(0x6A82, sw(p.process(Hex.decode("00A4040007A000000003101000"))))
    }

    @Test
    fun ctapMsgWithoutSelectFails() {
        val p = NfcCtapProcessor({ _, _ -> byteArrayOf(0) })
        assertEquals(0x6A82, sw(p.process(Hex.decode("80100000010400"))))
    }

    @Test
    fun commandChainingAssemblesRequest() {
        var received: ByteArray? = null
        val p = NfcCtapProcessor({ req, _ -> received = req; byteArrayOf(0) })
        p.process(select)
        assertEquals(0x9000, sw(p.process(Hex.decode("9010000003010203"))))
        assertEquals(0x9000, sw(p.process(Hex.decode("90100000020405"))))
        val r = p.process(Hex.decode("8010000002060700"))
        assertEquals(0x9000, sw(r))
        assertArrayEquals(Hex.decode("01020304050607"), received)
    }

    @Test
    fun longResponseIsChainedWithGetResponse() {
        val big = ByteArray(700) { it.toByte() }
        val p = NfcCtapProcessor({ _, _ -> big })
        p.process(select)
        val out = ByteArrayOutputStream()
        var r = p.process(Hex.decode("80100000010400"))
        while (true) {
            out.write(body(r))
            val s = sw(r)
            if (s == 0x9000) break
            assertEquals(0x61, s ushr 8)
            r = p.process(Hex.decode("00C0000000"))
        }
        assertArrayEquals(big, out.toByteArray())
    }

    @Test
    fun extendedLengthApduIsAccepted() {
        var received: ByteArray? = null
        val p = NfcCtapProcessor({ req, _ -> received = req; ByteArray(300) { 7 } })
        p.process(select)
        val r = p.process(Hex.decode("8010000000000104" + "0000"))
        assertArrayEquals(byteArrayOf(4), received)
        assertEquals(0x9000, sw(r))
        assertEquals(300, r.size - 2)
    }

    @Test
    fun endToEndGetInfoOverApdu() {
        val auth = Ctap2Authenticator(
            InMemoryCredentialStore(), FakePolicy(),
            { AuthenticatorConfig(ByteArray(16)) }, "nfc"
        )
        val p = NfcCtapProcessor({ req, ka -> auth.process(req, ka) })
        p.process(select)
        val out = ByteArrayOutputStream()
        var r = p.process(Hex.decode("80100000010400"))
        while (true) {
            out.write(body(r))
            if (sw(r) == 0x9000) break
            r = p.process(Hex.decode("00C0000000"))
        }
        val resp = out.toByteArray()
        assertEquals(0, resp[0].toInt())
        val info = Cbor.decode(resp, 1, resp.size - 1) as Map<*, *>
        assertEquals(listOf("FIDO_2_0", "FIDO_2_1"), info[1L])
    }

    @Test
    fun u2fApduIsNotSupported() {
        val p = NfcCtapProcessor({ _, _ -> byteArrayOf(0) })
        p.process(select)
        assertEquals(0x6D00, sw(p.process(Hex.decode("0003000000"))))
    }

    // ------------------------------------------------------------------ レビュー指摘 F-01 / F-02

    /** 短い APDU で送り、指定の GET RESPONSE で応答全体を組み立てる。 */
    private fun exchangeShort(p: NfcCtapProcessor, request: ByteArray, getResponse: String): ByteArray {
        val out = ByteArrayOutputStream()
        var off = 0
        while (request.size - off > 250) { // コマンドチェイニング (CLA 90)
            val part = request.copyOfRange(off, off + 250)
            assertEquals(0x9000, sw(p.process(byteArrayOf(0x90.toByte(), 0x10, 0, 0, part.size.toByte()) + part)))
            off += 250
        }
        val last = request.copyOfRange(off, request.size)
        var r = p.process(byteArrayOf(0x80.toByte(), 0x10, 0, 0, last.size.toByte()) + last + byteArrayOf(0))
        while (true) {
            out.write(body(r))
            val s = sw(r)
            if (s == 0x9000) break
            assertEquals("unexpected SW ${Integer.toHexString(s)}", 0x61, s ushr 8)
            r = p.process(Hex.decode(getResponse))
        }
        return out.toByteArray()
    }

    @Test
    fun getResponseAcceptsCla80AndCla00() {
        for (gr in listOf("80C0000000", "00C0000000")) {
            val big = ByteArray(700) { (it * 3).toByte() }
            val p = NfcCtapProcessor({ _, _ -> big })
            p.process(select)
            assertArrayEquals(big, exchangeShort(p, byteArrayOf(4), gr))
        }
    }

    @Test
    fun responseLengthBoundaries() {
        for (n in listOf(1, 255, 256, 257, 511, 512, 513)) {
            val data = ByteArray(n) { it.toByte() }
            val p = NfcCtapProcessor({ _, _ -> data })
            p.process(select)
            val first = p.process(Hex.decode("80100000010400"))
            if (n <= 256) {
                assertEquals(0x9000, sw(first))
            } else {
                assertEquals(0x61, sw(first) ushr 8)
                assertEquals(256, body(first).size)
                val left = n - 256
                assertEquals(if (left >= 256) 0 else left, sw(first) and 0xFF)
            }
            val p2 = NfcCtapProcessor({ _, _ -> data })
            p2.process(select)
            assertArrayEquals(data, exchangeShort(p2, byteArrayOf(4), "80C0000000"))
        }
    }

    @Test
    fun getResponseWithBadP1P2KeepsThePendingResponse() {
        val big = ByteArray(400) { it.toByte() }
        val p = NfcCtapProcessor({ _, _ -> big })
        p.process(select)
        val first = p.process(Hex.decode("80100000010400"))
        assertEquals(0x61, sw(first) ushr 8)
        assertEquals(0x6A86, sw(p.process(Hex.decode("80C0010000"))))
        val rest = p.process(Hex.decode("80C0000000"))
        assertEquals(0x9000, sw(rest))
        assertArrayEquals(big, body(first) + body(rest))
    }

    @Test
    fun extendedRequestGetsTheWholeResponseAtOnce() {
        val big = ByteArray(1500) { it.toByte() }
        // Le = 0000
        val p = NfcCtapProcessor({ _, _ -> big })
        p.process(select)
        val r = p.process(Hex.decode("80100000000001040000"))
        assertEquals(0x9000, sw(r))
        assertArrayEquals(big, body(r))
        // Le 省略 (python-fido2 の拡張長モード)
        val p2 = NfcCtapProcessor({ _, _ -> big })
        p2.process(select)
        val r2 = p2.process(Hex.decode("8010000000000104"))
        assertEquals(0x9000, sw(r2))
        assertArrayEquals(big, body(r2))
    }

    @Test
    fun extendedRequestWithExplicitShortLeIsChained() {
        val big = ByteArray(1500) { it.toByte() }
        val p = NfcCtapProcessor({ _, _ -> big })
        p.process(select)
        val r = p.process(Hex.decode("80100000000001040400")) // Le = 1024
        assertEquals(1024, body(r).size)
        assertEquals(0x61, sw(r) ushr 8)
        val out = ByteArrayOutputStream().apply { write(body(r)) }
        var next = r
        while (sw(next) != 0x9000) {
            next = p.process(Hex.decode("80C0000000"))
            out.write(body(next))
        }
        assertArrayEquals(big, out.toByteArray())
    }

    @Test
    fun chainIsDiscardedAfterAnUnsupportedInstruction() {
        var received: ByteArray? = null
        val p = NfcCtapProcessor({ req, _ -> received = req; byteArrayOf(0) })
        p.process(select)
        assertEquals(0x9000, sw(p.process(Hex.decode("901000000101"))))
        assertEquals(0x6D00, sw(p.process(Hex.decode("80FF0000"))))
        assertEquals(0x9000, sw(p.process(Hex.decode("80100000010400"))))
        assertArrayEquals(byteArrayOf(4), received)
    }

    @Test
    fun chainIsDiscardedAfterAMalformedApduOrGetResponse() {
        var received: ByteArray? = null
        val p = NfcCtapProcessor({ req, _ -> received = req; byteArrayOf(0) })
        p.process(select)
        p.process(Hex.decode("901000000101"))
        assertEquals(0x6700, sw(p.process(Hex.decode("8010000005AA")))) // Lc と長さの不一致
        p.process(Hex.decode("80100000010400"))
        assertArrayEquals(byteArrayOf(4), received)

        p.process(Hex.decode("901000000101"))
        p.process(Hex.decode("80C0000000"))
        p.process(Hex.decode("80100000010400"))
        assertArrayEquals(byteArrayOf(4), received)
    }

    @Test
    fun packedSelfAttestationOverCla80GetResponse() {
        val store = InMemoryCredentialStore()
        val auth = Ctap2Authenticator(
            store, FakePolicy(),
            { AuthenticatorConfig(ByteArray(16), attestationMode = AttestationMode.SELF) }, "nfc"
        )
        val p = NfcCtapProcessor({ req, ka -> auth.process(req, ka) })
        p.process(select)
        val params = linkedMapOf<Long, Any?>(
            1L to ByteArray(32) { 1 },
            2L to linkedMapOf("id" to "example.com", "name" to "Example"),
            3L to linkedMapOf("id" to ByteArray(64) { 2 }, "name" to "a".repeat(64), "displayName" to "b".repeat(64)),
            4L to listOf(linkedMapOf("alg" to -7L, "type" to "public-key")),
            7L to linkedMapOf("rk" to true)
        )
        val request = byteArrayOf(0x01) + Cbor.encode(params)
        val resp = exchangeShort(p, request, "80C0000000")
        assertEquals(0, resp[0].toInt())
        val m = Cbor.decode(resp, 1, resp.size - 1) as Map<*, *>
        assertEquals("packed", m[1L])
        val authData = m[2L] as ByteArray
        val credIdLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        val (cose, _) = Cbor.decodeFirst(authData, 55 + credIdLen)
        val key = TestCrypto.publicKeyFromCose(cose as Map<*, *>)
        val sig = (m[3L] as Map<*, *>)["sig"] as ByteArray
        assertTrue(TestCrypto.verify(key, authData + (params[1L] as ByteArray), sig))
    }
}
