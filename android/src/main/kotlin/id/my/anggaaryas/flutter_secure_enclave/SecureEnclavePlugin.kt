package id.my.anggaaryas.flutter_secure_enclave

import android.content.Context
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.FlutterPlugin.FlutterPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyPairGenerator
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

class SecureEnclavePlugin: FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val KEY_ALIAS = "my_key_alias"
    private val KEYSTORE_PROVIDER = "AndroidKeyStore"

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "secure_enclave")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            "generateKeyPair" -> {
                try {
                    generateKeyPair()
                    result.success(mapOf("status" to "success", "data" to true))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "removeKey" -> {
                try {
                    deleteKeyPair()
                    result.success(mapOf("status" to "success", "data" to true))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "isKeyCreated" -> {
                try {
                    val isCreated = isKeyCreated()
                    result.success(mapOf("status" to "success", "data" to isCreated))
                } catch (e: Exception) {
                    result.success(mapOf("status" to "success", "data" to false))
                }
            }
            "getPublicKey" -> {
                try {
                    val publicKey = getPublicKey()
                    result.success(mapOf("status" to "success", "data" to publicKey))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "encrypt" -> {
                try {
                   val param = call.arguments as? Map<String, Any>
                    val message = param?.get("message") as? String ?: ""
                    val tag = param?.get("tag") as? String ?: ""
                    var password: String? = null
                    param?.let {
                        if (it.containsKey("password")) {
                            password = it["password"] as? String
                        }
                    }

                    val encrypted = encrypt(message)
                    result.success(mapOf("status" to "success", "data" to encrypted))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "decrypt" -> {
                try {
                val param = call.arguments as? Map<String, Any>
                val messageBytes = (param?.get("message") as? ByteArray) ?: byteArrayOf()
                // val message = FlutterStandardTypedData(StandardMessageCodec(), messageBytes)
                val tag = param?.get("tag") as? String ?: ""
                var password: String? = null
                param?.let {
                    if (it.containsKey("password")) {
                        password = it["password"] as? String
                    }
                }
                    val decrypted = decrypt(messageBytes)
                    result.success(mapOf("status" to "success", "data" to decrypted))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "sign" -> {
                try {
                    val param = call.arguments as? Map<String, Any>
                    val messageBytes = (param?.get("message") as? ByteArray) ?: byteArrayOf()
                    // val message = FlutterStandardTypedData(StandardMessageCodec(), messageBytes)
                    val tag = param?.get("tag") as? String ?: ""
                    var password: String? = null
                    param?.let {
                        if (it.containsKey("password")) {
                            password = it["password"] as? String
                        }
                    }

                    val signature = sign(messageBytes)
                    result.success(mapOf("status" to "success", "data" to signature))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "verify" -> {
                try {
               
                    val param = call.arguments as? Map<String, Any>
                    val tag = param?.get("tag") as? String ?: ""
                    val signatureText = param?.get("signature") as? String ?: ""
                    val plainText = param?.get("plainText") as? String ?: ""
                    var password: String? = null
                    param?.let {
                        if (it.containsKey("password")) {
                            password = it["password"] as? String
                        }
                    }

                    val isValid = verify(plainText.toByteArray(), signatureText.toByteArray())
                    result.success(mapOf("status" to "success", "data" to isValid))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    private fun generateKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER)
        keyPairGenerator.initialize(KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(2048)
            .build())
        keyPairGenerator.generateKeyPair()
    }

    private fun deleteKeyPair() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun isKeyCreated(): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.containsAlias(KEY_ALIAS)
    }

    private fun getPublicKey(): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    private fun encrypt(message: String): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromKeyStore())
        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    private fun decrypt(message: ByteArray): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromKeyStore())
        val decryptedBytes = cipher.doFinal(message)
        return String(decryptedBytes)
    }

    private fun sign(message: ByteArray): String {
        val privateKey = getPrivateKeyFromKeyStore()
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(message)
        val signatureBytes = signature.sign()
        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    private fun verify(plainText: ByteArray, signatureBytes: ByteArray): Boolean {
        val publicKey = getPublicKeyFromKeyStore()
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(plainText)
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

    override fun onDetachedFromEngine(@NonNull binding: FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}
