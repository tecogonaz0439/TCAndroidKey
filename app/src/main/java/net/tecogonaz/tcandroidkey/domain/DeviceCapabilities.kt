// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.domain

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.nfc.NfcAdapter

/** 端末の機能 (NFC / HCE / StrongBox / 画面ロック) の状態。 */
data class DeviceCapabilities(
    val hasNfc: Boolean = false,
    val nfcEnabled: Boolean = false,
    val hasHce: Boolean = false,
    val hasStrongBox: Boolean = false,
    val deviceSecure: Boolean = false,
    val hasBluetooth: Boolean = false
) {
    companion object {
        fun read(context: Context): DeviceCapabilities {
            val pm = context.packageManager
            val nfc = runCatching { NfcAdapter.getDefaultAdapter(context) }.getOrNull()
            return DeviceCapabilities(
                hasNfc = nfc != null,
                nfcEnabled = nfc?.isEnabled == true,
                hasHce = pm.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION),
                hasStrongBox = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
                deviceSecure = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true,
                hasBluetooth = pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)
            )
        }
    }
}
