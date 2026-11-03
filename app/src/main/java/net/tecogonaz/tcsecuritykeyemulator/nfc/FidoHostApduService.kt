// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import net.tecogonaz.tcsecuritykeyemulator.AppContainer
import net.tecogonaz.tcsecuritykeyemulator.appContainer
import net.tecogonaz.tcsecuritykeyemulator.data.LogLevel
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeepAlive
import net.tecogonaz.tcsecuritykeyemulator.fido.nfc.NfcCtapProcessor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicLong

/**
 * NFC カードエミュレーション (HCE) で FIDO アプレット (AID A0000006472F0001) として振る舞うサービス。
 *
 * 読み取り機 (PC/SC リーダー、他の Android 端末等) からの APDU を [NfcCtapProcessor] で処理する。
 * CTAP 処理 (Keystore 署名など) は時間がかかる場合があるため、メインスレッドではなくワーカーで実行し、
 * [sendResponseApdu] で非同期に応答する。
 *
 * アプリ前面表示中かつ本人確認済みでない場合は SELECT を拒否する (= セキュリティキーとして見えない)。
 *
 * 読み取り機との接続 (activate〜[onDeactivated]) ごとに世代番号を持ち、APDU の処理開始時と応答の送出時に照合する。
 * [HostApduService.sendResponseApdu] には接続を指定する手段がないため、切断前に受信した要求の応答が
 * 再接続後の読み取り機へ送られないよう、古い世代の処理は取り消し・応答を破棄する。
 */
class FidoHostApduService : HostApduService() {
    private lateinit var container: AppContainer
    private lateinit var authenticator: Ctap2Authenticator
    private lateinit var processor: NfcCtapProcessor
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "fido-nfc").apply { isDaemon = true }
    }

    /** 接続の世代。[onDeactivated] で即座に進める (メインスレッド)。 */
    private val connection = AtomicLong(0)

    /** 受信時の接続世代に結び付いた取消トークン。切断されると isCancelled = true になる。 */
    private inner class ConnectionToken(private val generation: Long) : KeepAlive {
        override fun send(status: Int) {} // NFC では keepalive を送らない
        override val isCancelled: Boolean get() = connection.get() != generation
    }

    override fun onCreate() {
        super.onCreate()
        container = appContainer
        val policy = container.session.policy(TRANSPORT, blocking = false)
        authenticator = container.newAuthenticator(TRANSPORT, listOf("nfc"), policy)
        processor = NfcCtapProcessor(
            ctapHandler = { request, token -> authenticator.process(request, token) },
            selectGate = { container.session.nfcSelectGate() }
        )
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        val token = ConnectionToken(connection.get())
        try {
            worker.execute {
                // 切断後に処理待ちになっていた APDU は処理しない
                if (token.isCancelled) return@execute
                val response = try {
                    processor.process(commandApdu, token)
                } catch (e: Exception) {
                    container.eventLog.log(LogLevel.ERROR, TRANSPORT, "APDU processing failed: $e")
                    NfcCtapProcessor.sw(0x6F00)
                }
                if (token.isCancelled) {
                    container.eventLog.log(LogLevel.WARNING, TRANSPORT, "response discarded: reader disconnected during processing")
                    return@execute
                }
                runCatching { sendResponseApdu(response) }
            }
        } catch (e: RejectedExecutionException) {
            return NfcCtapProcessor.sw(0x6F00)
        }
        return null
    }

    override fun onDeactivated(reason: Int) {
        // 世代は即座に進める (ワーカーで処理中の要求を取り消し、その応答を送らない)。
        connection.incrementAndGet()
        try {
            worker.execute {
                val wasSelected = processor.isSelected
                processor.reset()
                authenticator.resetSession()
                if (wasSelected) {
                    val why = if (reason == HostApduService.DEACTIVATION_LINK_LOSS) "link loss" else "deselected"
                    container.eventLog.log(LogLevel.INFO, TRANSPORT, "reader disconnected ($why)")
                }
            }
        } catch (e: RejectedExecutionException) {
            // サービス破棄後
        }
    }

    override fun onDestroy() {
        connection.incrementAndGet()
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        const val TRANSPORT: String = "NFC"
    }
}
