// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.hid

import net.tecogonaz.tcandroidkey.fido.cbor.Cbor
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthenticatorConfig
import net.tecogonaz.tcandroidkey.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import net.tecogonaz.tcandroidkey.fido.testutil.FakePolicy
import net.tecogonaz.tcandroidkey.fido.testutil.InMemoryCredentialStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executor

class CtapHidProcessorTest {

    private val sent = mutableListOf<ByteArray>()
    private var cancelled = false
    private val auth = Ctap2Authenticator(InMemoryCredentialStore(), FakePolicy(), { AuthenticatorConfig(ByteArray(16)) }, "hid")
    private val direct = Executor { it.run() }
    private val processor = CtapHidProcessor(
        ctapHandler = { req, ka -> ka.send(KeepAlive.STATUS_PROCESSING); auth.process(req, ka) },
        sendReport = { sent += it },
        onCancel = { cancelled = true },
        worker = direct
    )

    private fun initPacket(cid: Int, cmd: Int, payload: ByteArray, total: Int = payload.size): ByteArray {
        val r = ByteArray(64)
        r[0] = (cid ushr 24).toByte(); r[1] = (cid ushr 16).toByte(); r[2] = (cid ushr 8).toByte(); r[3] = cid.toByte()
        r[4] = cmd.toByte()
        r[5] = (total ushr 8).toByte(); r[6] = total.toByte()
        System.arraycopy(payload, 0, r, 7, minOf(57, payload.size))
        return r
    }

    private fun contPacket(cid: Int, seq: Int, payload: ByteArray): ByteArray {
        val r = ByteArray(64)
        r[0] = (cid ushr 24).toByte(); r[1] = (cid ushr 16).toByte(); r[2] = (cid ushr 8).toByte(); r[3] = cid.toByte()
        r[4] = seq.toByte()
        System.arraycopy(payload, 0, r, 5, minOf(59, payload.size))
        return r
    }

    private fun send(cid: Int, cmd: Int, payload: ByteArray) {
        processor.onReport(initPacket(cid, cmd, payload))
        var off = 57
        var seq = 0
        while (off < payload.size) {
            processor.onReport(contPacket(cid, seq++, payload.copyOfRange(off, payload.size)))
            off += 59
        }
    }

    /** 送信済みパケットからメッセージ (cmd, payload) を順に復元する。 */
    private fun messages(): List<Pair<Int, ByteArray>> {
        val result = mutableListOf<Pair<Int, ByteArray>>()
        var i = 0
        while (i < sent.size) {
            val p = sent[i]
            val cmd = p[4].toInt() and 0xFF
            val len = ((p[5].toInt() and 0xFF) shl 8) or (p[6].toInt() and 0xFF)
            val out = ByteArrayOutputStream()
            out.write(p, 7, minOf(57, len))
            i++
            while (out.size() < len) {
                out.write(sent[i], 5, minOf(59, len - out.size()))
                i++
            }
            result += cmd to out.toByteArray()
        }
        return result
    }

    private fun init(): Int {
        val nonce = ByteArray(8) { (it + 1).toByte() }
        send(CtapHidProcessor.BROADCAST_CID, CtapHidProcessor.CMD_INIT, nonce)
        val (cmd, payload) = messages().last()
        assertEquals(CtapHidProcessor.CMD_INIT, cmd)
        assertArrayEquals(nonce, payload.copyOfRange(0, 8))
        assertEquals(17, payload.size)
        assertTrue((payload[16].toInt() and CtapHidProcessor.CAPABILITY_CBOR) != 0)
        sent.clear()
        return ((payload[8].toInt() and 0xFF) shl 24) or ((payload[9].toInt() and 0xFF) shl 16) or
            ((payload[10].toInt() and 0xFF) shl 8) or (payload[11].toInt() and 0xFF)
    }

    @Test
    fun initAllocatesChannelAndPingEchoesMultiPacketPayload() {
        val cid = init()
        val data = ByteArray(300) { (it * 7).toByte() }
        send(cid, CtapHidProcessor.CMD_PING, data)
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_PING, cmd)
        assertArrayEquals(data, payload)
    }

    @Test
    fun cborGetInfoWithKeepalive() {
        val cid = init()
        send(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x04))
        val msgs = messages()
        assertEquals(CtapHidProcessor.CMD_KEEPALIVE, msgs[0].first)
        val (cmd, payload) = msgs.last()
        assertEquals(CtapHidProcessor.CMD_CBOR, cmd)
        assertEquals(0, payload[0].toInt())
        val info = Cbor.decode(payload, 1, payload.size - 1) as Map<*, *>
        assertEquals(listOf("FIDO_2_0"), info[1L])
    }

    @Test
    fun unknownChannelIsRejected() {
        send(0x12345678, CtapHidProcessor.CMD_PING, byteArrayOf(1))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_CHANNEL, payload[0].toInt())
    }

    @Test
    fun ctap1MsgIsNotSupported() {
        val cid = init()
        send(cid, CtapHidProcessor.CMD_MSG, byteArrayOf(0, 3, 0, 0))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_CMD, payload[0].toInt())
    }

    @Test
    fun wrongSequenceAbortsTransaction() {
        val cid = init()
        processor.onReport(initPacket(cid, CtapHidProcessor.CMD_PING, ByteArray(57), total = 100))
        processor.onReport(contPacket(cid, 5, ByteArray(43)))
        val (cmd, payload) = messages().single()
        assertEquals(CtapHidProcessor.CMD_ERROR, cmd)
        assertEquals(CtapHidProcessor.ERR_INVALID_SEQ, payload[0].toInt())
    }

    @Test
    fun cancelWhileBusyInvokesCallback() {
        var pendingTask: Runnable? = null
        val sent2 = mutableListOf<ByteArray>()
        var cancel = false
        val p = CtapHidProcessor(
            ctapHandler = { _, _ -> byteArrayOf(0x2D) },
            sendReport = { sent2 += it },
            onCancel = { cancel = true },
            worker = { pendingTask = it }
        )
        p.onReport(initPacket(CtapHidProcessor.BROADCAST_CID, CtapHidProcessor.CMD_INIT, ByteArray(8)))
        val initResp = sent2.last()
        val cid = ((initResp[15].toInt() and 0xFF) shl 24) or ((initResp[16].toInt() and 0xFF) shl 16) or
            ((initResp[17].toInt() and 0xFF) shl 8) or (initResp[18].toInt() and 0xFF)
        p.onReport(initPacket(cid, CtapHidProcessor.CMD_CBOR, byteArrayOf(0x02, 0xA0.toByte())))
        p.onReport(initPacket(cid, CtapHidProcessor.CMD_CANCEL, ByteArray(0)))
        assertTrue(cancel)
        pendingTask!!.run()
        val last = sent2.last()
        assertEquals(CtapHidProcessor.CMD_CBOR, last[4].toInt() and 0xFF)
        assertEquals(0x2D, last[7].toInt())
    }
}
