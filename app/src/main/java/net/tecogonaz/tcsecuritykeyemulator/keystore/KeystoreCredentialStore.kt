// SPDX-FileCopyrightText: 2026 tecogonaz <tecogonaz@kusugami-lab.net>
// SPDX-License-Identifier: Apache-2.0

package net.tecogonaz.tcsecuritykeyemulator.keystore

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
import net.tecogonaz.tcsecuritykeyemulator.domain.AppSettings
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CredentialOptions
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CredentialStore
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapException
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.CtapStatus
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.EcKeys
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.Hex
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeySecurityLevel
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.KeyUseNotAuthorizedException
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.StoredCredential
import net.tecogonaz.tcsecuritykeyemulator.fido.ctap2.UserEntity
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Android Keystore (TEE / StrongBox) に秘密鍵を保持するクレデンシャルストア。
 *
 * - 1 クレデンシャルにつき 1 つの EC P-256 鍵 (エイリアス `fido_cred_<credentialIdHex>`) を生成する。
 * - 鍵はユーザー認証 (Class 3 生体認証または画面ロック資格情報) から一定時間のみ署名に使用でき、
 *   端末ロック中は使用できない (`setUnlockedDeviceRequired`)。
 * - 秘密鍵は Keystore の外へ取り出せない。端末のバックアップ・移行の対象にもならない。
 * - hmac-secret 拡張を要求された credential には HMAC-SHA256 鍵 (エイリアス `fido_hmac_<credentialIdHex>`) を生成し、
 *   CredRandom (UV あり用 / なし用) を Keystore 内の HMAC で導出する。認証・ロックの条件は署名鍵と同じ。
 */
class KeystoreCredentialStore(
    context: Context,
    private val preferStrongBox: () -> Boolean
) : CredentialStore {
    /** メタデータの読み込み状態。 */
    enum class Availability { NOT_LOADED, AVAILABLE, UNAVAILABLE }

    data class StorageStatus(val availability: Availability, val error: String? = null)

    private val appContext = context.applicationContext
    private val metadata = MetadataStore(appContext.filesDir)
    private val random = SecureRandom()

    /** 保存済みの内容と一致するスナップショット。保存に成功してから差し替える (書き換えない)。 */
    private var cache: Map<String, StoredCredential> = emptyMap()
    private var loaded = false

    private val _credentials = MutableStateFlow<List<StoredCredential>>(emptyList())

    /** UI 表示用のクレデンシャル一覧 (作成日時の新しい順)。 */
    val credentials: StateFlow<List<StoredCredential>> = _credentials.asStateFlow()

    private val _status = MutableStateFlow(StorageStatus(Availability.NOT_LOADED))

    /**
     * メタデータの状態。[Availability.UNAVAILABLE] の間は、既存のファイルを上書きしないよう
     * 登録・認証・個別削除を拒否する (全削除による初期化のみ可能)。
     */
    val status: StateFlow<StorageStatus> = _status.asStateFlow()

    val isStrongBoxAvailable: Boolean
        get() = appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun keyStore(): KeyStore = KeyStore.getInstance(MetadataStore.ANDROID_KEYSTORE).apply { load(null) }

    /**
     * メタデータを読み込み、Keystore に鍵が存在しないエントリを除去する。
     * 読み込めない場合は [status] を UNAVAILABLE にして例外を投げる (次の操作時に再試行する)。
     */
    @Synchronized
    fun load() {
        ensureLoaded()
    }

    private fun ensureLoaded() {
        if (loaded) return
        try {
            val ks = keyStore()
            val entries = metadata.load()
            val next = LinkedHashMap<String, StoredCredential>()
            entries.filter { ks.containsAlias(alias(it.id)) }.forEach { next[it.idHex] = it }
            if (next.size != entries.size) metadata.save(next.values)
            commit(next)
            loaded = true
            _status.value = StorageStatus(Availability.AVAILABLE)
        } catch (e: Exception) {
            _status.value = StorageStatus(Availability.UNAVAILABLE, e.message ?: e.javaClass.simpleName)
            throw CtapException(CtapStatus.ERR_OTHER, "credential storage unavailable: ${e.message}")
        }
    }

    /** [next] を保存し、成功した場合のみキャッシュ・UI へ反映する。 */
    private fun saveAndCommit(next: Map<String, StoredCredential>) {
        try {
            metadata.save(next.values)
        } catch (e: Exception) {
            throw CtapException(CtapStatus.ERR_OTHER, "failed to save credential metadata: ${e.message}")
        }
        commit(next)
    }

    private fun commit(next: Map<String, StoredCredential>) {
        cache = next
        _credentials.value = next.values.sortedWith(StoredCredential.NEWEST_FIRST)
    }

    @Synchronized
    override fun create(
        rpId: String,
        rpName: String?,
        user: UserEntity,
        discoverable: Boolean,
        options: CredentialOptions
    ): StoredCredential {
        ensureLoaded()
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
        if (options.hmacSecret) {
            try {
                try {
                    generateHmacKey(hmacAlias(id), useStrongBox)
                } catch (e: StrongBoxUnavailableException) {
                    generateHmacKey(hmacAlias(id), false)
                }
            } catch (e: Exception) {
                // hmac-secret を要求された登録は、CredRandom を作れなければ全体を失敗させる
                runCatching { keyStore().deleteEntry(alias) }
                runCatching { keyStore().deleteEntry(hmacAlias(id)) }
                throw CtapException(CtapStatus.ERR_OPERATION_DENIED, "hmac-secret key generation failed: ${e.message}")
            }
        }
        val (x, y) = EcKeys.coordinates(keyPair.public as ECPublicKey)
        val credential = StoredCredential(
            id = id,
            rpId = rpId,
            rpName = rpName,
            user = user,
            discoverable = discoverable,
            // 時計が巻き戻っても既存のどの credential より新しくする (上書き登録と discoverable の順序のため)
            createdAtMillis = StoredCredential.nextCreatedAt(System.currentTimeMillis(), cache.values),
            lastUsedAtMillis = null,
            signCount = 0,
            publicKeyX = x,
            publicKeyY = y,
            securityLevel = securityLevelOf(keyPair.private),
            hmacSecret = options.hmacSecret,
            credProtect = options.credProtect,
            label = StoredCredential.normalizeLabel(options.label)
        )
        try {
            saveAndCommit(LinkedHashMap(cache).apply { put(credential.idHex, credential) })
        } catch (e: Exception) {
            // メタデータのない鍵を残さない
            runCatching { keyStore().deleteEntry(alias) }
            runCatching { keyStore().deleteEntry(hmacAlias(id)) }
            throw e
        }
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

    private fun generateHmacKey(alias: String, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                AppSettings.KEYSTORE_AUTH_VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, MetadataStore.ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
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
        ensureLoaded()
        return ids.mapNotNull { cache[Hex.encode(it)] }.filter { it.rpId == rpId }.distinctBy { it.idHex }
    }

    @Synchronized
    override fun findDiscoverable(rpId: String): List<StoredCredential> {
        ensureLoaded()
        return cache.values.filter { it.rpId == rpId && it.discoverable }.sortedWith(StoredCredential.NEWEST_FIRST)
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

    /**
     * CredRandom = HMAC-SHA256(K, "CredRandomWithUV" / "CredRandomWithoutUV")。K は Keystore 内の HMAC 鍵で、外へ取り出さない。
     * HMAC 鍵がない credential (hmac-secret なしで登録) は null。
     */
    override fun credRandom(credential: StoredCredential, userVerified: Boolean): ByteArray? {
        if (!credential.hmacSecret) return null
        val key = keyStore().getKey(hmacAlias(credential.id), null) as? SecretKey ?: return null
        val mac = Mac.getInstance("HmacSHA256")
        try {
            mac.init(key)
        } catch (e: UserNotAuthenticatedException) {
            throw KeyUseNotAuthorizedException("user authentication expired", e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyUseNotAuthorizedException("key permanently invalidated (lock screen changed)", e)
        } catch (e: InvalidKeyException) {
            throw KeyUseNotAuthorizedException("key unusable: ${e.message}", e)
        }
        return try {
            mac.doFinal(if (userVerified) LABEL_WITH_UV else LABEL_WITHOUT_UV)
        } catch (e: Exception) {
            throw KeyUseNotAuthorizedException("HMAC failed: ${e.message}", e)
        }
    }

    @Synchronized
    override fun incrementSignCount(credential: StoredCredential): Long {
        ensureLoaded()
        val current = cache[credential.idHex] ?: throw CtapException(CtapStatus.ERR_INVALID_CREDENTIAL)
        val updated = current.copy(signCount = current.signCount + 1, lastUsedAtMillis = System.currentTimeMillis())
        // 署名前に永続化する (保存できなければ署名しない)
        saveAndCommit(LinkedHashMap(cache).apply { put(updated.idHex, updated) })
        return updated.signCount
    }

    @Synchronized
    override fun list(): List<StoredCredential> {
        ensureLoaded()
        return cache.values.sortedWith(StoredCredential.NEWEST_FIRST)
    }

    @Synchronized
    override fun updateUser(id: ByteArray, user: UserEntity): Boolean {
        ensureLoaded()
        val current = cache[Hex.encode(id)] ?: return false
        val updated = current.copy(user = current.user.copy(name = user.name, displayName = user.displayName))
        saveAndCommit(LinkedHashMap(cache).apply { put(updated.idHex, updated) })
        return true
    }

    @Synchronized
    override fun updateLabel(id: ByteArray, label: String?): Boolean {
        ensureLoaded()
        val current = cache[Hex.encode(id)] ?: return false
        val updated = current.copy(label = StoredCredential.normalizeLabel(label))
        if (updated == current) return true
        saveAndCommit(LinkedHashMap(cache).apply { put(updated.idHex, updated) })
        return true
    }

    /** メタデータから外してから鍵を削除する (保存に失敗した場合は何も変えない)。 */
    @Synchronized
    override fun delete(id: ByteArray): Boolean {
        ensureLoaded()
        val key = Hex.encode(id)
        val removed = cache.containsKey(key)
        if (removed) saveAndCommit(LinkedHashMap(cache).apply { remove(key) })
        // 鍵の削除に失敗しても、メタデータのない鍵は全削除 (エイリアスの接頭辞で検索) で除去される
        runCatching { keyStore().deleteEntry(alias(id)) }
        runCatching { keyStore().deleteEntry(hmacAlias(id)) }
        return removed
    }

    /**
     * 全クレデンシャル (本アプリが生成した全鍵) とメタデータを削除する。
     * メタデータを読み込めない状態からの初期化にも使う (メタデータの暗号鍵も作り直す)。
     */
    @Synchronized
    override fun deleteAll() {
        val ks = keyStore()
        ks.aliases().toList().filter { it.startsWith(ALIAS_PREFIX) || it.startsWith(HMAC_ALIAS_PREFIX) }.forEach {
            runCatching { ks.deleteEntry(it) }
        }
        metadata.deleteFile()
        metadata.deleteKey()
        commit(emptyMap())
        loaded = true
        _status.value = StorageStatus(Availability.AVAILABLE)
    }

    private fun alias(id: ByteArray): String = ALIAS_PREFIX + Hex.encode(id)

    private fun hmacAlias(id: ByteArray): String = HMAC_ALIAS_PREFIX + Hex.encode(id)

    companion object {
        const val ALIAS_PREFIX = "fido_cred_"

        /** hmac-secret の HMAC 鍵のエイリアスの接頭辞 (変更しない識別子)。 */
        const val HMAC_ALIAS_PREFIX = "fido_hmac_"
        private val LABEL_WITH_UV = "CredRandomWithUV".toByteArray(Charsets.US_ASCII)
        private val LABEL_WITHOUT_UV = "CredRandomWithoutUV".toByteArray(Charsets.US_ASCII)
        const val CREDENTIAL_ID_LENGTH = 32
    }
}
