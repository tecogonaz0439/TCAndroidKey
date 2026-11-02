// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.bluetooth

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHidDevice
import android.bluetooth.BluetoothHidDeviceAppSdpSettings
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Intent
import android.content.pm.PackageManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.tecogonaz.tcandroidkey.AppContainer
import net.tecogonaz.tcandroidkey.data.LogLevel
import net.tecogonaz.tcandroidkey.fido.hid.CtapHidProcessor
import java.util.concurrent.Executors

/**
 * Bluetooth HID Device プロファイルで FIDO HID (CTAPHID) セキュリティキーとして振る舞う (実験的機能)。
 *
 * PC 側で本端末を Bluetooth デバイスとしてペアリングすると、OS からは
 * HID usage page 0xF1D0 の FIDO デバイスとして認識される。
 * NFC と異なり通信中に待機できるため、未確認の場合はその場で本人確認ダイアログを表示して待つ。
 *
 * 注意: ホスト OS / ブラウザによっては Bluetooth 接続の FIDO HID デバイスを扱わない場合がある。
 */
@SuppressLint("MissingPermission")
class BluetoothHidAuthenticator(private val container: AppContainer) {

    enum class Status { UNSUPPORTED, PERMISSION_REQUIRED, BLUETOOTH_OFF, STOPPED, STARTING, WAITING_FOR_HOST, CONNECTED, ERROR }

    data class State(val status: Status, val hostName: String? = null, val message: String? = null)

    private val context = container.appContext
    private val adapter: BluetoothAdapter? = context.getSystemService(BluetoothManager::class.java)?.adapter
    private val callbackExecutor = Executors.newSingleThreadExecutor { r -> Thread(r, "fido-bt-cb").apply { isDaemon = true } }
    private val ctapWorker = Executors.newSingleThreadExecutor { r -> Thread(r, "fido-bt-ctap").apply { isDaemon = true } }
    private val policy = container.session.policy(TRANSPORT, blocking = true)
    private val authenticator = container.newAuthenticator(TRANSPORT, listOf("usb"), policy)
    // CTAPHID_CANCEL・切断・停止による取消は、CtapHidProcessor が要求ごとのトークン (keepAlive) で伝える。
    private val processor = CtapHidProcessor(
        ctapHandler = { cid, request, keepAlive -> authenticator.process(request, keepAlive, cid) },
        sendReport = ::sendReport,
        worker = ctapWorker
    )

    private val _state = MutableStateFlow(State(if (adapter == null) Status.UNSUPPORTED else Status.STOPPED))
    val state: StateFlow<State> = _state.asStateFlow()

    @Volatile
    private var hid: BluetoothHidDevice? = null

    @Volatile
    private var host: BluetoothDevice? = null

    /** HID アプリとして登録済みか (プロキシの有無とは別。OS がバックグラウンド化等で解除することがある)。 */
    @Volatile
    private var registered = false

    /** 利用者が開始を指示しているか。停止後に遅れて届いたプロキシ接続で登録しないために使う。 */
    @Volatile
    private var desiredStarted = false

    fun hasPermission(): Boolean =
        context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED

    /** HID デバイスとして登録し、ホストからの接続を待つ。 */
    fun start() {
        val a = adapter ?: run { _state.value = State(Status.UNSUPPORTED); return }
        if (!hasPermission()) {
            _state.value = State(Status.PERMISSION_REQUIRED)
            return
        }
        if (!a.isEnabled) {
            _state.value = State(Status.BLUETOOTH_OFF)
            return
        }
        desiredStarted = true
        hid?.let { proxy ->
            // プロキシは残っているが登録が解除されている場合は、登録し直す
            if (!registered) register(proxy)
            return
        }
        _state.value = State(Status.STARTING)
        val requested = try {
            a.getProfileProxy(context, serviceListener, BluetoothProfile.HID_DEVICE)
        } catch (e: SecurityException) {
            false
        }
        if (!requested) {
            _state.value = State(Status.UNSUPPORTED, message = "HID Device profile is not available")
        }
    }

    /**
     * HID デバイスの登録を解除する。UI スレッドから呼ばれるため、ブロックしない
     * (本人確認待ちの操作は取消トークンで中断され、CTAP の状態はロックを待たずに破棄する)。
     */
    fun stop() {
        desiredStarted = false
        registered = false
        processor.reset()
        authenticator.resetSession()
        val h = hid ?: run {
            if (_state.value.status != Status.UNSUPPORTED) _state.value = State(Status.STOPPED)
            return
        }
        runCatching { h.unregisterApp() }
        runCatching { adapter?.closeProfileProxy(BluetoothProfile.HID_DEVICE, h) }
        hid = null
        host = null
        _state.value = State(Status.STOPPED)
    }

    /** 本端末を一定時間「検出可能」にするための Intent (BLUETOOTH_ADVERTISE 権限が必要)。 */
    fun discoverableIntent(): Intent =
        Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
            .putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, DISCOVERABLE_SECONDS)

    private val serviceListener = object : BluetoothProfile.ServiceListener {
        override fun onServiceConnected(profile: Int, proxy: BluetoothProfile?) {
            if (profile != BluetoothProfile.HID_DEVICE || proxy == null) return
            val device = proxy as BluetoothHidDevice
            if (!desiredStarted) {
                // 開始要求の後、接続前に停止された
                runCatching { adapter?.closeProfileProxy(BluetoothProfile.HID_DEVICE, device) }
                return
            }
            hid = device
            register(device)
        }

        override fun onServiceDisconnected(profile: Int) {
            if (profile != BluetoothProfile.HID_DEVICE) return
            hid = null
            host = null
            registered = false
            processor.reset()
            authenticator.resetSession()
            _state.value = State(Status.STOPPED)
        }
    }

    private fun register(device: BluetoothHidDevice) {
        val sdp = BluetoothHidDeviceAppSdpSettings(
            SDP_NAME,
            SDP_DESCRIPTION,
            SDP_PROVIDER,
            BluetoothHidDevice.SUBCLASS1_NONE,
            CtapHidProcessor.REPORT_DESCRIPTOR
        )
        _state.value = State(Status.STARTING)
        val ok = try {
            device.registerApp(sdp, null, null, callbackExecutor, hidCallback)
        } catch (e: SecurityException) {
            false
        }
        if (!ok) {
            _state.value = State(Status.ERROR, message = "registerApp failed")
            log(LogLevel.ERROR, "failed to register HID device")
        }
    }

    private val hidCallback = object : BluetoothHidDevice.Callback() {
        override fun onAppStatusChanged(pluggedDevice: BluetoothDevice?, registered: Boolean) {
            this@BluetoothHidAuthenticator.registered = registered
            if (registered) {
                _state.value = State(Status.WAITING_FOR_HOST)
                log(LogLevel.INFO, "registered as FIDO HID device; waiting for host")
            } else if (hid != null) {
                // OS による自動解除 (アプリのバックグラウンド化など)。次の start() で登録し直す。
                processor.reset()
                authenticator.resetSession()
                host = null
                _state.value = State(Status.STOPPED)
                log(LogLevel.INFO, "HID device registration ended; it will be registered again when the app returns")
            }
        }

        override fun onConnectionStateChanged(device: BluetoothDevice?, state: Int) {
            when (state) {
                BluetoothProfile.STATE_CONNECTED -> {
                    host = device
                    val name = runCatching { device?.name }.getOrNull() ?: device?.address
                    _state.value = State(Status.CONNECTED, hostName = name)
                    log(LogLevel.INFO, "host connected: $name", logcatMessage = "host connected")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    if (host == null || host == device) host = null
                    processor.reset()
                    authenticator.resetSession()
                    if (hid != null) _state.value = State(Status.WAITING_FOR_HOST)
                    log(LogLevel.INFO, "host disconnected")
                }
            }
        }

        override fun onGetReport(device: BluetoothDevice?, type: Byte, id: Byte, bufferSize: Int) {
            val d = device ?: return
            runCatching { hid?.replyReport(d, type, id, ByteArray(CtapHidProcessor.REPORT_SIZE)) }
        }

        override fun onSetReport(device: BluetoothDevice?, type: Byte, id: Byte, data: ByteArray?) {
            if (type == BluetoothHidDevice.REPORT_TYPE_OUTPUT && data != null) onOutputReport(data)
            val d = device ?: return
            runCatching { hid?.reportError(d, BluetoothHidDevice.ERROR_RSP_SUCCESS) }
        }

        override fun onInterruptData(device: BluetoothDevice?, reportId: Byte, data: ByteArray?) {
            if (data != null) onOutputReport(data)
        }

        override fun onVirtualCableUnplug(device: BluetoothDevice?) {
            host = null
            processor.reset()
            authenticator.resetSession()
        }
    }

    private fun onOutputReport(data: ByteArray) {
        val report = when {
            data.size == CtapHidProcessor.REPORT_SIZE + 1 && data[0].toInt() == 0 -> data.copyOfRange(1, data.size)
            data.size >= CtapHidProcessor.REPORT_SIZE -> data.copyOfRange(0, CtapHidProcessor.REPORT_SIZE)
            else -> data.copyOf(CtapHidProcessor.REPORT_SIZE)
        }
        processor.onReport(report)
    }

    private fun sendReport(report: ByteArray) {
        val h = hid ?: return
        val d = host ?: return
        try {
            h.sendReport(d, 0, report)
        } catch (e: SecurityException) {
            log(LogLevel.ERROR, "sendReport denied: ${e.message}")
        }
    }

    private fun log(level: LogLevel, message: String, logcatMessage: String = message) =
        container.eventLog.log(level, TRANSPORT, message, logcatMessage)

    companion object {
        const val TRANSPORT: String = "Bluetooth"
        private const val SDP_NAME = "TCAndroidKey"
        private const val SDP_DESCRIPTION = "FIDO2 security key"
        private const val SDP_PROVIDER = "tecogonaz"
        private const val DISCOVERABLE_SECONDS = 120
    }
}
