// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

import net.tecogonaz.tcsecuritykeyemulator.fido.cbor.has

/** credProtect 拡張 (CTAP 2.1 §12.1、DD-01 §12.3)。 */
object CredProtect {
    const val ID: String = "credProtect"

    /** レベル 1: UV なしでも使える (既定)。 */
    const val USER_VERIFICATION_OPTIONAL: Int = 1

    /** レベル 2: allowList なし (discoverable の検索) では UV が必要。 */
    const val USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST: Int = 2

    /** レベル 3: 常に UV が必要。 */
    const val USER_VERIFICATION_REQUIRED: Int = 3

    /**
     * MakeCredential の extensions の credProtect を返す。指定がなければ null。
     * 整数でなければ `0x11`、1〜3 以外は `0x02 INVALID_PARAMETER`。
     */
    fun requested(extensions: Map<*, *>?): Int? {
        if (extensions == null || !extensions.has(ID)) return null
        val value = extensions[ID] as? Long ?: throw CtapException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        if (value !in 1L..3L) throw CtapException(CtapStatus.ERR_INVALID_PARAMETER, "invalid credProtect level $value")
        return value.toInt()
    }

    /**
     * GetAssertion で使える credential に絞る (CTAP 2.1 §6.2.2 手順 7.4・7.5)。
     *
     * @param userVerified 応答の UV フラグ
     * @param allowList allowList で credential を指定したか
     */
    fun filter(credentials: List<StoredCredential>, userVerified: Boolean, allowList: Boolean): List<StoredCredential> =
        credentials.filter {
            when (it.credProtect) {
                USER_VERIFICATION_REQUIRED -> userVerified
                USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST -> userVerified || allowList
                else -> true
            }
        }
}
