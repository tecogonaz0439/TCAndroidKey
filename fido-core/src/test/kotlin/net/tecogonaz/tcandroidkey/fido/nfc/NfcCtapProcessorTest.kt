// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.nfc

import net.tecogonaz.tcandroidkey.fido.cbor.Cbor
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthenticatorConfig
import net.tecogonaz.tcandroidkey.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcandroidkey.fido.ctap2.Hex
import net.tecogonaz.tcandroidkey.fido.testutil.FakePolicy
import net.tecogonaz.tcandroidkey.fido.testutil.InMemoryCredentialStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream

class NfcCtapProcessorTest {

    private val select = Hex.decode("00A4040008A0000006472F000100")

    private fun sw(resp: ByteArray): Int =
        ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)

    private fun body(resp: ByteArray): ByteArray = resp.copyOfRange(0, resp.size - 2)

    @Test
    fun selectReturnsVersion() {
        val p = NfcCtapProcessor({ byteArrayOf(0) })
        val r = p.process(select)
        assertEquals(0x9000, sw(r))
        assertEquals("FIDO_2_0", String(body(r)))
    }

    @Test
    fun selectIsRejectedWhenGateClosed() {
        val p = NfcCtapProcessor({ byteArrayOf(0) }, selectGate = { false })
        assertEquals(0x6A82, sw(p.process(select)))
        assertEquals(0x6A82, sw(p.process(Hex.decode("80100000010400"))))
    }

    @Test
    fun otherAidIsNotFound() {
        val p = NfcCtapProcessor({ byteArrayOf(0) })
        assertEquals(0x6A82, sw(p.process(Hex.decode("00A4040007A000000003101000"))))
    }

    @Test
    fun ctapMsgWithoutSelectFails() {
        val p = NfcCtapProcessor({ byteArrayOf(0) })
        assertEquals(0x6A82, sw(p.process(Hex.decode("80100000010400"))))
    }

    @Test
    fun commandChainingAssemblesRequest() {
        var received: ByteArray? = null
        val p = NfcCtapProcessor({ received = it; byteArrayOf(0) })
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
        val p = NfcCtapProcessor({ big })
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
        val p = NfcCtapProcessor({ received = it; ByteArray(300) { 7 } })
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
        val p = NfcCtapProcessor({ auth.process(it) })
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
        assertEquals(listOf("FIDO_2_0"), info[1L])
    }

    @Test
    fun u2fApduIsNotSupported() {
        val p = NfcCtapProcessor({ byteArrayOf(0) })
        p.process(select)
        assertEquals(0x6D00, sw(p.process(Hex.decode("0003000000"))))
    }
}
