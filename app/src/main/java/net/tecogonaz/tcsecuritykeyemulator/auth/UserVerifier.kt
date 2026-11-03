// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.auth

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal

/** 端末の本人確認手段の状態。 */
enum class VerificationAvailability {
    AVAILABLE,

    /** 画面ロック (PIN / パターン / パスワード) が未設定。Keystore 鍵を生成できない。 */
    NO_SECURE_LOCK_SCREEN,

    /** 生体認証のみ設定時に、Class 3 生体認証が未登録・非対応。 */
    NO_STRONG_BIOMETRIC,
    UNAVAILABLE
}

/**
 * プラットフォーム標準の BiometricPrompt による本人確認。
 *
 * - 許可する認証手段は Class 3 (BIOMETRIC_STRONG) 生体認証と、設定により画面ロック資格情報。
 * - 成功すると Android Keystore に認証トークンが渡され、時間制限付きの FIDO 鍵が署名可能になる。
 * - androidx.biometric や Google Play 開発者サービスには依存しない。
 */
class UserVerifier(private val activity: Activity) {
    private var cancellation: CancellationSignal? = null

    val isShowing: Boolean get() = cancellation != null

    fun availability(biometricOnly: Boolean): VerificationAvailability {
        val keyguard = activity.getSystemService(KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) return VerificationAvailability.NO_SECURE_LOCK_SCREEN
        val bm = activity.getSystemService(BiometricManager::class.java)
            ?: return VerificationAvailability.UNAVAILABLE
        return when (bm.canAuthenticate(authenticators(biometricOnly))) {
            BiometricManager.BIOMETRIC_SUCCESS -> VerificationAvailability.AVAILABLE
            else -> if (biometricOnly) VerificationAvailability.NO_STRONG_BIOMETRIC else VerificationAvailability.UNAVAILABLE
        }
    }

    /**
     * 本人確認ダイアログを表示する。
     *
     * @param onResult 成功時 true。キャンセル・失敗時 false とエラーメッセージ。
     */
    fun verify(
        title: String,
        subtitle: String?,
        biometricOnly: Boolean,
        negativeLabel: String,
        onResult: (success: Boolean, message: String?) -> Unit
    ) {
        if (cancellation != null) return
        val builder = BiometricPrompt.Builder(activity)
            .setTitle(title)
            .setAllowedAuthenticators(authenticators(biometricOnly))
            .setConfirmationRequired(false)
        if (subtitle != null) builder.setSubtitle(subtitle)
        if (biometricOnly) {
            // DEVICE_CREDENTIAL を許可しない場合はキャンセルボタンが必須。
            builder.setNegativeButton(negativeLabel, activity.mainExecutor) { _, _ ->
                cancellation = null
                onResult(false, null)
            }
        }
        val prompt = builder.build()
        val signal = CancellationSignal()
        cancellation = signal
        prompt.authenticate(signal, activity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                cancellation = null
                onResult(true, null)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                cancellation = null
                onResult(false, errString.toString())
            }
        })
    }

    fun cancel() {
        cancellation?.cancel()
        cancellation = null
    }

    companion object {
        fun authenticators(biometricOnly: Boolean): Int =
            if (biometricOnly) Authenticators.BIOMETRIC_STRONG
            else Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL

        fun isDeviceSecure(context: Context): Boolean =
            context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
    }
}
