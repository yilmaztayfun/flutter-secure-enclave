package id.my.anggaaryas.flutter_secure_enclave

import id.my.anggaaryas.flutter_secure_enclave.model.*
import id.my.anggaaryas.flutter_secure_enclave.factory.*
import android.content.Context
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.FlutterPlugin.FlutterPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import javax.crypto.Cipher
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.util.*
import io.flutter.plugin.common.StandardMessageCodec
import io.flutter.plugin.common.StandardMethodCodec
import io.flutter.plugin.common.StandardMethodCodec.INSTANCE

interface SECoreProtocol {
    @Throws(Exception::class)
    fun generateKeyPair(accessControlParam: AccessControlParam): KeyPair

    @Throws(Exception::class)
    fun removeKey(): Boolean

    @Throws(Exception::class)
    fun isKeyCreated(): Boolean?

    @Throws(Exception::class)
    fun getPublicKey(): String?

    @Throws(Exception::class)
    fun encrypt(message: String): ByteArray?

    @Throws(Exception::class)
    fun decrypt(message: ByteArray): String?

    @Throws(Exception::class)
    fun sign(message: ByteArray): String?

    @Throws(Exception::class)
    fun verify(plainText: String, signature: String): Boolean
}

class SECore : SECoreProtocol {
    private val KEY_ALIAS = "mtls.burgan.com.tr"
    private val KEYSTORE_PROVIDER = "AndroidKeyStore"

    override fun generateKeyPair(accessControlParam: AccessControlParam): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER)

        val parameterSpecBuilder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(2048)

        val parameterSpec = parameterSpecBuilder.build()
        keyPairGenerator.initialize(parameterSpec)
        val keyPair = keyPairGenerator.generateKeyPair()

        return keyPair
    }

    override fun removeKey(): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        keyStore.deleteEntry(KEY_ALIAS)
        return true
    }

    internal fun getSecKey(): KeyPair? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
        return if (privateKey != null && publicKey != null) KeyPair(publicKey, privateKey) else null
    }

    override fun isKeyCreated(): Boolean? {
        val secKey = getSecKey()
        return secKey != null
    }

    override fun getPublicKey(): String? {
        val publicKey = getPublicKeyFromKeyStore()
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    override fun encrypt(message: String): ByteArray? {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromKeyStore())
        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return encryptedBytes;
    }

    override fun decrypt(message: ByteArray): String? {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromKeyStore())
        val decryptedBytes = cipher.doFinal(message)
        return String(decryptedBytes)
    }

    override fun sign(message: ByteArray): String? {
        val privateKey = getPrivateKeyFromKeyStore()
        val signatureInstance = Signature.getInstance("SHA256withRSA")
        signatureInstance.initSign(privateKey)
        signatureInstance.update(message)
        val signatureBytes = signatureInstance.sign()
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    override fun verify(plainText: String, signatureText: String): Boolean {
        val publicKey = getPublicKeyFromKeyStore()
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(plainText.toByteArray())
        val signatureBytes = Base64.getDecoder().decode(signatureText)
        return signature.verify(signatureBytes)
    }

    private fun getPublicKeyFromKeyStore(): PublicKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getCertificate(KEY_ALIAS).publicKey
    }

    private fun getPrivateKeyFromKeyStore(): PrivateKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getKey(KEY_ALIAS, null) as PrivateKey
    }
}