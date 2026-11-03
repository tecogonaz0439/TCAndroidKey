// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.tecogonaz.tcsecuritykeyemulator.AppContainer
import net.tecogonaz.tcsecuritykeyemulator.TCSecurityKeyEmulatorApp
import net.tecogonaz.tcsecuritykeyemulator.auth.AuthSessionState
import net.tecogonaz.tcsecuritykeyemulator.bluetooth.BluetoothHidAuthenticator
import net.tecogonaz.tcsecuritykeyemulator.data.LogEntry
import net.tecogonaz.tcsecuritykeyemulator.data.LogLevel
import net.tecogonaz.tcsecuritykeyemulator.domain.AppSettings
import net.tecogonaz.tcsecuritykeyemulator.domain.DeviceCapabilities
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.StoredCredential
import net.tecogonaz.tcsecuritykeyemulator.keystore.KeystoreCredentialStore

class MainViewModel(private val container: AppContainer) : ViewModel() {
    val settings: StateFlow<AppSettings> = container.settings.settings
    val session: StateFlow<AuthSessionState> = container.session.state
    val credentials: StateFlow<List<StoredCredential>> = container.credentialStore.credentials
    val storageStatus: StateFlow<KeystoreCredentialStore.StorageStatus> = container.credentialStore.status
    val events: StateFlow<List<LogEntry>> = container.eventLog.entries
    val bluetooth: StateFlow<BluetoothHidAuthenticator.State> = container.bluetooth.state

    private val _capabilities = MutableStateFlow(DeviceCapabilities())
    val capabilities: StateFlow<DeviceCapabilities> = _capabilities.asStateFlow()

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 4)

    /** スナックバーに表示するメッセージ。 */
    val messages: SharedFlow<String> = _messages.asSharedFlow()

    fun showMessage(text: String) {
        _messages.tryEmit(text)
    }

    init {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { container.credentialStore.load() }.onFailure {
                container.eventLog.log(LogLevel.ERROR, "Keystore", "failed to load credentials: $it")
            }
        }
    }

    fun refreshCapabilities() {
        _capabilities.value = DeviceCapabilities.read(container.appContext)
    }

    fun arm() = container.session.arm()

    fun disarm() = container.session.disarm("stopped by user")

    fun updateSettings(transform: (AppSettings) -> AppSettings) = container.settings.update(transform)

    fun deleteCredential(credential: StoredCredential) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { container.credentialStore.delete(credential.id) }
                .onSuccess {
                    container.eventLog.log(
                        LogLevel.INFO, "Keystore", "deleted credential for ${credential.rpId}",
                        logcatMessage = "deleted a credential"
                    )
                }
                .onFailure { container.eventLog.log(LogLevel.ERROR, "Keystore", "failed to delete credential: ${it.message}") }
        }
    }

    /** 全削除。メタデータを読み込めない状態からの初期化にも使う。 */
    fun deleteAllCredentials() {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { container.credentialStore.deleteAll() }
                .onSuccess { container.eventLog.log(LogLevel.INFO, "Keystore", "deleted all credentials") }
                .onFailure { container.eventLog.log(LogLevel.ERROR, "Keystore", "failed to delete credentials: ${it.message}") }
        }
    }

    fun clearLog() = container.eventLog.clear()

    fun startBluetooth() = container.bluetooth.start()

    fun stopBluetooth() = container.bluetooth.stop()

    companion object {
        val Factory: ViewModelProvider.Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY] as TCSecurityKeyEmulatorApp
                MainViewModel(app.container)
            }
        }
    }
}
