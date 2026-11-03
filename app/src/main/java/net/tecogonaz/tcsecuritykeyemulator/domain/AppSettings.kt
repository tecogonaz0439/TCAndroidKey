// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.domain

import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.AttestationMode

enum class AppTheme { SYSTEM, LIGHT, DARK }

/**
 * アプリ設定。
 *
 * @property authWindowSeconds 本人確認後、認証を受け付ける時間 (秒)。
 * @property oneTimeAuthorization 1 回の本人確認で 1 回の登録/認証のみ許可する。
 * @property biometricOnly 本人確認を生体認証 (Class 3) のみに限定し、PIN/パターン等を許可しない。
 * @property promptOnTap 未確認のまま読み取り機にかざしたとき、本人確認ダイアログを自動表示する。
 * @property allowResetFromClient クライアント (OS の「セキュリティキーのリセット」等) からの全削除を許可する。
 * @property preferStrongBox 新規鍵を StrongBox に生成する (非対応端末では TEE)。
 * @property bluetoothEnabled Bluetooth HID トランスポート (実験的) を有効にする。
 * @property noticeAcknowledged 初回起動時の注意書き (テスト専用であること) を確認済みか。
 */
data class AppSettings(
    val theme: AppTheme = AppTheme.SYSTEM,
    val authWindowSeconds: Int = DEFAULT_AUTH_WINDOW_SECONDS,
    val oneTimeAuthorization: Boolean = true,
    val biometricOnly: Boolean = false,
    val promptOnTap: Boolean = true,
    val attestationMode: AttestationMode = AttestationMode.NONE,
    val allowResetFromClient: Boolean = false,
    val preferStrongBox: Boolean = true,
    val bluetoothEnabled: Boolean = false,
    val noticeAcknowledged: Boolean = false
) {
    companion object {
        const val DEFAULT_AUTH_WINDOW_SECONDS: Int = 60
        val AUTH_WINDOW_CHOICES: List<Int> = listOf(15, 30, 60, 120, 300)

        /**
         * Keystore 鍵に設定するユーザー認証の有効期間 (秒)。
         * アプリ側の受付時間 ([AUTH_WINDOW_CHOICES] の最大値) 以上である必要がある。
         */
        const val KEYSTORE_AUTH_VALIDITY_SECONDS: Int = 300
    }
}
