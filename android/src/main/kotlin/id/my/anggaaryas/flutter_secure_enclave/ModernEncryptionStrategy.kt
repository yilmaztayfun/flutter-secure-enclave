package id.my.anggaaryas.flutter_secure_enclave

import id.my.anggaaryas.flutter_secure_enclave.model.*
import id.my.anggaaryas.flutter_secure_enclave.factory.*
import java.math.BigInteger;
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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import java.util.*
import io.flutter.plugin.common.StandardMessageCodec
import io.flutter.plugin.common.StandardMethodCodec
import io.flutter.plugin.common.StandardMethodCodec.INSTANCE

class ModernEncryptionStrategy : EncryptionStrategy {
    private val KEYSTORE_PROVIDER = "BurganKeyStore"

    override fun generateKeyPair(accessControlParam: AccessControlParam): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER)

        val alias = accessControlParam.tag
        val parameterSpecBuilder = KeyGenParameterSpec.Builder(
            alias,
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

    override fun removeKey(tag: String): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        keyStore.deleteEntry(tag)
        return true
    }

    internal fun getSecKey(tag: String): KeyPair? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(tag, null) as PrivateKey
        val publicKey = keyStore.getCertificate(tag)?.publicKey
        return if (privateKey != null && publicKey != null) KeyPair(publicKey, privateKey) else null
    }

    override fun isKeyCreated(tag: String): Boolean? {
        val secKey = getSecKey(tag)
        return secKey != null
    }

    override fun getPublicKey(tag: String): String? {
        val publicKey = getPublicKeyFromKeyStore(tag)
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    override fun encrypt(message: String, tag: String): ByteArray? {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromKeyStore(tag))
        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return encryptedBytes;
    }

    override fun decrypt(message: ByteArray, tag: String): String? {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromKeyStore(tag))
        val decryptedBytes = cipher.doFinal(message)
        return String(decryptedBytes)
    }

    override fun sign(tag: String, message: ByteArray): String? {
        val privateKey = getPrivateKeyFromKeyStore(tag)
        val signatureInstance = Signature.getInstance("SHA256withRSA")
        signatureInstance.initSign(privateKey)
        signatureInstance.update(message)
        val signatureBytes = signatureInstance.sign()
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    override fun verify(tag: String, plainText: String, signatureText: String): Boolean {
        val publicKey = getPublicKeyFromKeyStore(tag)
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(plainText.toByteArray())
        val signatureBytes = Base64.getDecoder().decode(signatureText)
        return signature.verify(signatureBytes)
    }

    private fun getPublicKeyFromKeyStore(tag: String): PublicKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getCertificate(tag).publicKey
    }

    private fun getPrivateKeyFromKeyStore(tag: String): PrivateKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getKey(tag, null) as PrivateKey
    }
}