// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator

import android.app.Application
import android.content.Context
import net.tecogonaz.tcsecuritykeyemulator.auth.AuthSessionManager
import net.tecogonaz.tcsecuritykeyemulator.bluetooth.BluetoothHidAuthenticator
import net.tecogonaz.tcsecuritykeyemulator.data.EventLogRepository
import net.tecogonaz.tcsecuritykeyemulator.data.SettingsRepository
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthorizationPolicy
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AuthenticatorConfig
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Ctap2Authenticator
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.keystore.KeystoreCredentialStore

/**
 * 手動 DI コンテナ。アプリプロセスにつき 1 つ。
 * (Google Play 開発者サービスや DI フレームワークには依存しない)
 */
class AppContainer(context: Context) {
    val appContext: Context = context.applicationContext
    val settings = SettingsRepository(appContext)
    val eventLog = EventLogRepository()
    val credentialStore = KeystoreCredentialStore(appContext) { settings.current.preferStrongBox }
    val session = AuthSessionManager(settings, eventLog)
    val bluetooth: BluetoothHidAuthenticator by lazy { BluetoothHidAuthenticator(this) }

    fun authenticatorConfig(transports: List<String>): AuthenticatorConfig {
        val s = settings.current
        return AuthenticatorConfig(
            aaguid = AAGUID,
            attestationMode = s.attestationMode,
            transports = transports,
            allowReset = s.allowResetFromClient
        )
    }

    /** トランスポートセッション用の CTAP2 認証器を生成する。 */
    fun newAuthenticator(transport: String, transports: List<String>, policy: AuthorizationPolicy): Ctap2Authenticator =
        Ctap2Authenticator(
            store = credentialStore,
            policy = policy,
            configProvider = { authenticatorConfig(transports) },
            transportName = transport,
            listener = { event -> eventLog.onAuthenticatorEvent(event) }
        )

    companion object {
        /** 本アプリ (TCSecurityKeyEmulator) 固有の AAGUID: 523283ca-3c2c-48b5-8bff-a722f900e190 */
        val AAGUID: ByteArray = Hex.decode("523283ca3c2c48b58bffa722f900e190")
    }
}

class TCSecurityKeyEmulatorApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}

val Context.appContainer: AppContainer
    get() = (applicationContext as TCSecurityKeyEmulatorApp).container
