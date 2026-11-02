// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.fido.testutil

import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationPolicy
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationRequest
import net.tecogonaz.tcandroidkey.fido.ctap2.AuthorizationResult
import net.tecogonaz.tcandroidkey.fido.ctap2.CredentialStore
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapStatus
import net.tecogonaz.tcandroidkey.fido.ctap2.EcKeys
import net.tecogonaz.tcandroidkey.fido.ctap2.KeepAlive
import net.tecogonaz.tcandroidkey.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcandroidkey.fido.ctap2.StoredCredential
import net.tecogonaz.tcandroidkey.fido.ctap2.UserEntity
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** JCA ソフトウェア鍵を用いたテスト用のクレデンシャルストア。 */
class InMemoryCredentialStore : CredentialStore {
    private val creds = LinkedHashMap<String, StoredCredential>()
    private val keys = HashMap<String, PrivateKey>()
    private var now = 1_000L
    private val random = SecureRandom()

    override fun create(rpId: String, rpName: String?, user: UserEntity, discoverable: Boolean): StoredCredential {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val id = ByteArray(32).also { random.nextBytes(it) }
        val (x, y) = EcKeys.coordinates(kp.public as ECPublicKey)
        val c = StoredCredential(id, rpId, rpName, user, discoverable, now++, null, 0, x, y, KeySecurityLevel.SOFTWARE)
        creds[c.idHex] = c
        keys[c.idHex] = kp.private
        return c
    }

    override fun findByIds(rpId: String, ids: List<ByteArray>): List<StoredCredential> =
        creds.values.filter { c -> c.rpId == rpId && ids.any { it.contentEquals(c.id) } }

    override fun findDiscoverable(rpId: String): List<StoredCredential> =
        creds.values.filter { it.rpId == rpId && it.discoverable }.sortedByDescending { it.createdAtMillis }

    override fun deleteDiscoverable(rpId: String, userId: ByteArray) {
        creds.values.filter { it.rpId == rpId && it.discoverable && it.user.id.contentEquals(userId) }
            .forEach { delete(it.id) }
    }

    override fun sign(credential: StoredCredential, data: ByteArray): ByteArray {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(keys.getValue(credential.idHex))
        s.update(data)
        return s.sign()
    }

    override fun incrementSignCount(credential: StoredCredential): Long {
        val cur = creds.getValue(credential.idHex)
        val updated = cur.copy(signCount = cur.signCount + 1, lastUsedAtMillis = now++)
        creds[credential.idHex] = updated
        return updated.signCount
    }

    override fun list(): List<StoredCredential> = creds.values.toList()

    override fun delete(id: ByteArray): Boolean {
        val k = net.tecogonaz.tcandroidkey.fido.ctap2.Hex.encode(id)
        keys.remove(k)
        return creds.remove(k) != null
    }

    override fun deleteAll() {
        creds.clear()
        keys.clear()
    }
}

/** 呼び出し記録付きの設定可能なポリシー。 */
class FakePolicy(
    var result: AuthorizationResult = AuthorizationResult.Granted(userPresent = true, userVerified = true)
) : AuthorizationPolicy {
    val requests = mutableListOf<AuthorizationRequest>()
    val completed = mutableListOf<Pair<AuthorizationRequest, Boolean>>()

    override fun authorize(request: AuthorizationRequest, keepAlive: KeepAlive): AuthorizationResult {
        requests += request
        return result
    }

    override fun onOperationCompleted(request: AuthorizationRequest, success: Boolean) {
        completed += request to success
    }

    companion object {
        fun denied() = FakePolicy(AuthorizationResult.Denied(CtapStatus.ERR_OPERATION_DENIED, "denied"))
    }
}

object TestCrypto {
    fun publicKeyFromCose(cose: Map<*, *>): PublicKey {
        val x = BigInteger(1, cose[-2L] as ByteArray)
        val y = BigInteger(1, cose[-3L] as ByteArray)
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val spec = params.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), spec))
    }

    fun verify(key: PublicKey, data: ByteArray, sig: ByteArray): Boolean {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initVerify(key)
        s.update(data)
        return s.verify(sig)
    }

    fun sha256(b: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(b)
}
