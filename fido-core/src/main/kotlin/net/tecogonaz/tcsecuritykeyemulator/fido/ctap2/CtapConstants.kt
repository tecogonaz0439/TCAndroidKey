// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.fido.ctap2

/** CTAP2 コマンドコード (CTAP 2.1 §6)。 */
object CtapCommand {
    const val MAKE_CREDENTIAL: Int = 0x01
    const val GET_ASSERTION: Int = 0x02
    const val GET_INFO: Int = 0x04
    const val CLIENT_PIN: Int = 0x06
    const val RESET: Int = 0x07
    const val GET_NEXT_ASSERTION: Int = 0x08
    const val CREDENTIAL_MANAGEMENT: Int = 0x0A
    const val SELECTION: Int = 0x0B
    const val CREDENTIAL_MANAGEMENT_PRE: Int = 0x41

    fun name(cmd: Int): String = when (cmd) {
        MAKE_CREDENTIAL -> "authenticatorMakeCredential"
        GET_ASSERTION -> "authenticatorGetAssertion"
        GET_INFO -> "authenticatorGetInfo"
        CLIENT_PIN -> "authenticatorClientPIN"
        RESET -> "authenticatorReset"
        GET_NEXT_ASSERTION -> "authenticatorGetNextAssertion"
        CREDENTIAL_MANAGEMENT, CREDENTIAL_MANAGEMENT_PRE -> "authenticatorCredentialManagement"
        SELECTION -> "authenticatorSelection"
        else -> "unknown(0x%02X)".format(cmd)
    }
}

/** CTAP2 ステータスコード (CTAP 2.1 §8.2)。 */
object CtapStatus {
    const val OK: Int = 0x00
    const val ERR_INVALID_COMMAND: Int = 0x01
    const val ERR_INVALID_PARAMETER: Int = 0x02
    const val ERR_INVALID_LENGTH: Int = 0x03
    const val ERR_CBOR_UNEXPECTED_TYPE: Int = 0x11
    const val ERR_INVALID_CBOR: Int = 0x12
    const val ERR_MISSING_PARAMETER: Int = 0x14
    const val ERR_LIMIT_EXCEEDED: Int = 0x15
    const val ERR_CREDENTIAL_EXCLUDED: Int = 0x19
    const val ERR_PROCESSING: Int = 0x21
    const val ERR_INVALID_CREDENTIAL: Int = 0x22
    const val ERR_USER_ACTION_PENDING: Int = 0x23
    const val ERR_OPERATION_PENDING: Int = 0x24
    const val ERR_NO_OPERATIONS: Int = 0x25
    const val ERR_UNSUPPORTED_ALGORITHM: Int = 0x26
    const val ERR_OPERATION_DENIED: Int = 0x27
    const val ERR_KEY_STORE_FULL: Int = 0x28
    const val ERR_UNSUPPORTED_OPTION: Int = 0x2B
    const val ERR_INVALID_OPTION: Int = 0x2C
    const val ERR_KEEPALIVE_CANCEL: Int = 0x2D
    const val ERR_NO_CREDENTIALS: Int = 0x2E
    const val ERR_USER_ACTION_TIMEOUT: Int = 0x2F
    const val ERR_NOT_ALLOWED: Int = 0x30
    const val ERR_PIN_INVALID: Int = 0x31
    const val ERR_PIN_AUTH_INVALID: Int = 0x33
    const val ERR_PIN_NOT_SET: Int = 0x35
    const val ERR_PIN_REQUIRED: Int = 0x36
    const val ERR_UV_BLOCKED: Int = 0x3C
    const val ERR_REQUEST_TOO_LARGE: Int = 0x39
    const val ERR_UV_INVALID: Int = 0x3F
    const val ERR_OTHER: Int = 0x7F

    fun name(status: Int): String = when (status) {
        OK -> "CTAP2_OK"
        ERR_INVALID_COMMAND -> "CTAP1_ERR_INVALID_COMMAND"
        ERR_INVALID_PARAMETER -> "CTAP1_ERR_INVALID_PARAMETER"
        ERR_INVALID_LENGTH -> "CTAP1_ERR_INVALID_LENGTH"
        ERR_CBOR_UNEXPECTED_TYPE -> "CTAP2_ERR_CBOR_UNEXPECTED_TYPE"
        ERR_INVALID_CBOR -> "CTAP2_ERR_INVALID_CBOR"
        ERR_MISSING_PARAMETER -> "CTAP2_ERR_MISSING_PARAMETER"
        ERR_CREDENTIAL_EXCLUDED -> "CTAP2_ERR_CREDENTIAL_EXCLUDED"
        ERR_UNSUPPORTED_ALGORITHM -> "CTAP2_ERR_UNSUPPORTED_ALGORITHM"
        ERR_OPERATION_DENIED -> "CTAP2_ERR_OPERATION_DENIED"
        ERR_KEY_STORE_FULL -> "CTAP2_ERR_KEY_STORE_FULL"
        ERR_UNSUPPORTED_OPTION -> "CTAP2_ERR_UNSUPPORTED_OPTION"
        ERR_INVALID_OPTION -> "CTAP2_ERR_INVALID_OPTION"
        ERR_KEEPALIVE_CANCEL -> "CTAP2_ERR_KEEPALIVE_CANCEL"
        ERR_NO_CREDENTIALS -> "CTAP2_ERR_NO_CREDENTIALS"
        ERR_USER_ACTION_TIMEOUT -> "CTAP2_ERR_USER_ACTION_TIMEOUT"
        ERR_NOT_ALLOWED -> "CTAP2_ERR_NOT_ALLOWED"
        ERR_PIN_AUTH_INVALID -> "CTAP2_ERR_PIN_AUTH_INVALID"
        ERR_PIN_NOT_SET -> "CTAP2_ERR_PIN_NOT_SET"
        ERR_OTHER -> "CTAP1_ERR_OTHER"
        else -> "0x%02X".format(status)
    }
}

/** COSE アルゴリズム識別子。 */
object CoseAlgorithm {
    const val ES256: Long = -7
}

/** authenticatorData のフラグビット。 */
object AuthDataFlags {
    const val UP: Int = 0x01
    const val UV: Int = 0x04
    const val AT: Int = 0x40
    const val ED: Int = 0x80
}

/** CTAP2 処理中に発生したエラーをステータスコードとともに伝搬する例外。 */
class CtapException(val status: Int, message: String = CtapStatus.name(status)) : Exception(message)
