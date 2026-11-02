// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcandroidkey.keystore

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.tecogonaz.tcandroidkey.domain.AppSettings
import net.tecogonaz.tcandroidkey.fido.ctap2.CredentialStore
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapException
import net.tecogonaz.tcandroidkey.fido.ctap2.CtapStatus
import net.tecogonaz.tcandroidkey.fido.ctap2.EcKeys
import net.tecogonaz.tcandroidkey.fido.ctap2.Hex
import net.tecogonaz.tcandroidkey.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcandroidkey.fido.ctap2.KeyUseNotAuthorizedException
import net.tecogonaz.tcandroidkey.fido.ctap2.StoredCredential
import net.tecogonaz.tcandroidkey.fido.ctap2.UserEntity
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Android Keystore (TEE / StrongBox) に秘密鍵を保持するクレデンシャルストア。
 *
 * - 1 クレデンシャルにつき 1 つの EC P-256 鍵 (エイリアス `fido_cred_<credentialIdHex>`) を生成する。
 * - 鍵はユーザー認証 (Class 3 生体認証または画面ロック資格情報) から一定時間のみ署名に使用でき、
 *   端末ロック中は使用できない (`setUnlockedDeviceRequired`)。
 * - 秘密鍵は Keystore の外へ取り出せない。端末のバックアップ・移行の対象にもならない。
 */
class KeystoreCredentialStore(
    context: Context,
    private val preferStrongBox: () -> Boolean
) : CredentialStore {
    private val appContext = context.applicationContext
    private val metadata = MetadataStore(appContext.filesDir)
    private val random = SecureRandom()
    private val cache = LinkedHashMap<String, StoredCredential>()
    private var loaded = false

    private val _credentials = MutableStateFlow<List<StoredCredential>>(emptyList())

    /** UI 表示用のクレデンシャル一覧 (新しい順)。 */
    val credentials: StateFlow<List<StoredCredential>> = _credentials.asStateFlow()

    val isStrongBoxAvailable: Boolean
        get() = appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun keyStore(): KeyStore = KeyStore.getInstance(MetadataStore.ANDROID_KEYSTORE).apply { load(null) }

    /** メタデータを読み込み、Keystore に鍵が存在しないエントリを除去する。 */
    @Synchronized
    fun load() {
        if (loaded) return
        val ks = keyStore()
        val entries = runCatching { metadata.load() }.getOrElse { emptyList() }
        cache.clear()
        entries.filter { ks.containsAlias(alias(it.id)) }.forEach { cache[it.idHex] = it }
        loaded = true
        if (cache.size != entries.size) persist() else publish()
    }

    @Synchronized
    override fun create(rpId: String, rpName: String?, user: UserEntity, discoverable: Boolean): StoredCredential {
        load()
        val id = ByteArray(CREDENTIAL_ID_LENGTH).also { random.nextBytes(it) }
        val alias = alias(id)
        val useStrongBox = preferStrongBox() && isStrongBoxAvailable
        val keyPair = try {
            try {
                generateKeyPair(alias, useStrongBox)
            } catch (e: StrongBoxUnavailableException) {
                generateKeyPair(alias, false)
            }
        } catch (e: Exception) {
            // 画面ロック未設定などで鍵を生成できない
            throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "key generation failed: ${e.message}")
        }
        val (x, y) = EcKeys.coordinates(keyPair.public as ECPublicKey)
        val credential = StoredCredential(
            id = id,
            rpId = rpId,
            rpName = rpName,
            user = user,
            discoverable = discoverable,
            createdAtMillis = System.currentTimeMillis(),
            lastUsedAtMillis = null,
            signCount = 0,
            publicKeyX = x,
            publicKeyY = y,
            securityLevel = securityLevelOf(keyPair.private)
        )
        cache[credential.idHex] = credential
        persist()
        return credential
    }

    private fun generateKeyPair(alias: String, strongBox: Boolean): java.security.KeyPair {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                AppSettings.KEYSTORE_AUTH_VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, MetadataStore.ANDROID_KEYSTORE)
        generator.initialize(spec)
        return generator.generateKeyPair()
    }

    private fun securityLevelOf(key: PrivateKey): KeySecurityLevel = runCatching {
        val factory = KeyFactory.getInstance(key.algorithm, MetadataStore.ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java)
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TEE
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
            else -> KeySecurityLevel.UNKNOWN
        }
    }.getOrDefault(KeySecurityLevel.UNKNOWN)

    @Synchronized
    override fun findByIds(rpId: String, ids: List<ByteArray>): List<StoredCredential> {
        load()
        return ids.mapNotNull { cache[Hex.encode(it)] }.filter { it.rpId == rpId }.distinct()
    }

    @Synchronized
    override fun findDiscoverable(rpId: String): List<StoredCredential> {
        load()
        return cache.values.filter { it.rpId == rpId && it.discoverable }
            .sortedByDescending { it.lastUsedAtMillis ?: it.createdAtMillis }
    }

    @Synchronized
    override fun deleteDiscoverable(rpId: String, userId: ByteArray) {
        load()
        cache.values.filter { it.rpId == rpId && it.discoverable && it.user.id.contentEquals(userId) }
            .toList()
            .forEach { deleteInternal(it.id) }
        persist()
    }

    override fun sign(credential: StoredCredential, data: ByteArray): ByteArray {
        val ks = keyStore()
        val key = ks.getKey(alias(credential.id), null) as? PrivateKey
            ?: throw CtapException(CtapStatus.ERR_INVALID_CREDENTIAL, "key not found")
        val signature = Signature.getInstance("SHA256withECDSA")
        try {
            signature.initSign(key)
        } catch (e: UserNotAuthenticatedException) {
            throw KeyUseNotAuthorizedException("user authentication expired", e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyUseNotAuthorizedException("key permanently invalidated (lock screen changed)", e)
        } catch (e: InvalidKeyException) {
            throw KeyUseNotAuthorizedException("key unusable: ${e.message}", e)
        }
        signature.update(data)
        return try {
            signature.sign()
        } catch (e: Exception) {
            throw KeyUseNotAuthorizedException("signing failed: ${e.message}", e)
        }
    }

    @Synchronized
    override fun incrementSignCount(credential: StoredCredential): Long {
        load()
        val current = cache[credential.idHex] ?: throw CtapException(CtapStatus.ERR_INVALID_CREDENTIAL)
        val updated = current.copy(signCount = current.signCount + 1, lastUsedAtMillis = System.currentTimeMillis())
        cache[credential.idHex] = updated
        persist()
        return updated.signCount
    }

    @Synchronized
    override fun list(): List<StoredCredential> {
        load()
        return cache.values.sortedByDescending { it.createdAtMillis }
    }

    @Synchronized
    override fun delete(id: ByteArray): Boolean {
        load()
        val removed = deleteInternal(id)
        persist()
        return removed
    }

    private fun deleteInternal(id: ByteArray): Boolean {
        runCatching { keyStore().deleteEntry(alias(id)) }
        return cache.remove(Hex.encode(id)) != null
    }

    /** 全クレデンシャル (本アプリが生成した全鍵) を削除する。 */
    @Synchronized
    override fun deleteAll() {
        val ks = keyStore()
        ks.aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }.forEach {
            runCatching { ks.deleteEntry(it) }
        }
        cache.clear()
        loaded = true
        metadata.deleteFile()
        publish()
    }

    private fun persist() {
        metadata.save(cache.values)
        publish()
    }

    private fun publish() {
        _credentials.value = cache.values.sortedByDescending { it.createdAtMillis }
    }

    private fun alias(id: ByteArray): String = ALIAS_PREFIX + Hex.encode(id)

    companion object {
        const val ALIAS_PREFIX = "fido_cred_"
        const val CREDENTIAL_ID_LENGTH = 32
    }
}
