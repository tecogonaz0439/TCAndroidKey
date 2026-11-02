// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import net.tecogonaz.tcandroidkey.auth.UserVerifier
import net.tecogonaz.tcandroidkey.auth.VerificationAvailability
import net.tecogonaz.tcandroidkey.domain.AppTheme
import net.tecogonaz.tcandroidkey.nfc.FidoHostApduService
import net.tecogonaz.tcandroidkey.ui.AppRoot
import net.tecogonaz.tcandroidkey.ui.MainViewModel
import net.tecogonaz.tcandroidkey.ui.UiActions
import net.tecogonaz.tcandroidkey.ui.common.TestUseNoticeDialog
import net.tecogonaz.tcandroidkey.ui.theme.TCAndroidKeyTheme
import android.graphics.Color as AndroidColor

/**
 * 唯一の Activity。
 *
 * - onStart/onStop でセッションの「前面表示中」状態を切り替える (= アプリ起動中のみ認証可能)。
 * - onResume/onPause で本アプリの HCE サービスを優先サービスに設定する。
 * - 本人確認要求 (NFC タップ時・Bluetooth 待機時) を購読し、BiometricPrompt を表示する。
 */
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels { MainViewModel.Factory }
    private lateinit var verifier: UserVerifier
    private val container: AppContainer get() = appContainer

    private val bluetoothPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        if (result[Manifest.permission.BLUETOOTH_CONNECT] == true) {
            viewModel.startBluetooth()
        } else {
            viewModel.showMessage(getString(R.string.msg_bluetooth_permission_denied))
        }
    }

    private val discoverableLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 認証器の画面は他アプリから覗き見されないよう、スクリーンショット・画面共有を禁止する。
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        verifier = UserVerifier(this)

        val actions = UiActions(
            armWithVerification = ::armWithVerification,
            verifyThen = { title, action -> verifyThen(title, action) },
            openNfcSettings = { launchSafely(Intent(Settings.ACTION_NFC_SETTINGS)) },
            openSecuritySettings = { launchSafely(Intent(Settings.ACTION_SECURITY_SETTINGS)) },
            requestBluetoothPermission = ::requestBluetoothPermission,
            makeDiscoverable = {
                try {
                    discoverableLauncher.launch(container.bluetooth.discoverableIntent())
                } catch (e: Exception) {
                    launchSafely(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                }
            },
            openUrl = { url -> launchSafely(Intent(Intent.ACTION_VIEW, url.toUri())) },
            openAppLanguageSettings = {
                // TCSameuraDamMonitor と同様に、OS のアプリ別言語設定 (locales_config.xml の en / ja) を開く。
                launchSafely(Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", packageName, null)))
            }
        )

        setContent {
            val settings by viewModel.settings.collectAsStateWithLifecycle()
            val useDarkTheme = when (settings.theme) {
                AppTheme.SYSTEM -> isSystemInDarkTheme()
                AppTheme.LIGHT -> false
                AppTheme.DARK -> true
            }
            // システムバーの配色はテーマが変わったときだけ更新する (Composition 本体で Window を操作しない)。
            DisposableEffect(useDarkTheme) {
                enableEdgeToEdge(
                    statusBarStyle = if (useDarkTheme) {
                        SystemBarStyle.dark(scrim = AndroidColor.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(scrim = AndroidColor.TRANSPARENT, darkScrim = AndroidColor.TRANSPARENT)
                    },
                    navigationBarStyle = if (useDarkTheme) {
                        SystemBarStyle.dark(scrim = AndroidColor.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(scrim = AndroidColor.TRANSPARENT, darkScrim = AndroidColor.TRANSPARENT)
                    }
                )
                onDispose {}
            }
            TCAndroidKeyTheme(darkTheme = useDarkTheme) {
                AppRoot(viewModel = viewModel, actions = actions)
                // 初回起動時に注意書き (テスト専用・物理キーの代替として使用しない) を確認してもらう。
                if (!settings.noticeAcknowledged) {
                    TestUseNoticeDialog(onAcknowledge = { viewModel.updateSettings { it.copy(noticeAcknowledged = true) } })
                }
            }
        }

        // NFC タップ・Bluetooth 要求時の本人確認ダイアログ
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                container.session.verificationRequests.collect {
                    if (!verifier.isShowing && !container.session.isArmed()) armWithVerification()
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        container.session.setForeground(true)
        if (container.settings.current.bluetoothEnabled) viewModel.startBluetooth()
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshCapabilities()
        cardEmulation()?.let { ce ->
            runCatching { ce.setPreferredService(this, ComponentName(this, FidoHostApduService::class.java)) }
        }
    }

    override fun onPause() {
        cardEmulation()?.let { ce -> runCatching { ce.unsetPreferredService(this) } }
        super.onPause()
    }

    override fun onStop() {
        // 前面から外れたら即座に認証受付を解除する。
        container.session.setForeground(false)
        super.onStop()
    }

    override fun onDestroy() {
        if (isFinishing) {
            verifier.cancel()
            container.bluetooth.stop()
        }
        super.onDestroy()
    }

    private fun cardEmulation(): CardEmulation? {
        val adapter = NfcAdapter.getDefaultAdapter(this) ?: return null
        return runCatching { CardEmulation.getInstance(adapter) }.getOrNull()
    }

    private fun armWithVerification() {
        verifyThen(getString(R.string.verify_title_arm)) { viewModel.arm() }
    }

    private fun verifyThen(title: String, action: () -> Unit) {
        val biometricOnly = container.settings.current.biometricOnly
        when (verifier.availability(biometricOnly)) {
            VerificationAvailability.AVAILABLE -> Unit
            VerificationAvailability.NO_SECURE_LOCK_SCREEN -> {
                viewModel.showMessage(getString(R.string.msg_no_lock_screen))
                return
            }
            VerificationAvailability.NO_STRONG_BIOMETRIC -> {
                viewModel.showMessage(getString(R.string.msg_no_strong_biometric))
                return
            }
            VerificationAvailability.UNAVAILABLE -> {
                viewModel.showMessage(getString(R.string.msg_verification_unavailable))
                return
            }
        }
        verifier.verify(
            title = title,
            subtitle = getString(R.string.verify_subtitle),
            biometricOnly = biometricOnly,
            negativeLabel = getString(R.string.action_cancel)
        ) { success, message ->
            if (success) {
                action()
            } else if (message != null) {
                viewModel.showMessage(getString(R.string.msg_verification_failed, message))
            }
        }
    }

    private fun requestBluetoothPermission() {
        if (container.bluetooth.hasPermission()) {
            viewModel.startBluetooth()
        } else {
            bluetoothPermissionLauncher.launch(
                arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
            )
        }
    }

    private fun launchSafely(intent: Intent) {
        try {
            startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            viewModel.showMessage(getString(R.string.msg_cannot_open))
        }
    }
}
