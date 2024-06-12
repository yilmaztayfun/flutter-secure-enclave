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
    val seCore = SECore()

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "secure_enclave")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            "generateKeyPair" -> {
                try {
                    val param = call.arguments as? Map<String, Any?>
                    if(param != null){
                        val accessControlValue = param["accessControl"] as? Map<String, Any?>
                        if(accessControlValue != null){
                            val accessControlParam = AccessControlFactory(accessControlValue).build()
                            seCore.generateKeyPair(accessControlParam)
                            result.success(mapOf("status" to "success", "data" to true))
                        }                        
                    }else{
                        result.error("ERROR", "accessControl is empty", null)
                    }
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "removeKey" -> {
                try {
                    seCore.removeKey()
                    result.success(mapOf("status" to "success", "data" to true))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "isKeyCreated" -> {
                try {
                    val isCreated = seCore.isKeyCreated()
                    result.success(mapOf("status" to "success", "data" to isCreated))
                } catch (e: Exception) {
                    result.success(mapOf("status" to "success", "data" to false))
                }
            }
            "getPublicKey" -> {
                try {
                    val publicKey = seCore.getPublicKey()
                    result.success(mapOf("status" to "success", "data" to publicKey))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "encrypt" -> {
                try {
                    val param = call.arguments as? Map<String, Any>
                    val message = param?.get("message") as? String ?: ""
                    val encrypted = seCore.encrypt(message)
                    result.success(mapOf("status" to "success", "data" to encrypted))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "decrypt" -> {
                try {
                    val param = call.arguments as? Map<String, Any>
                    val messageBytes = (param?.get("message") as? ByteArray) ?: byteArrayOf()
                    val decrypted = seCore.decrypt(messageBytes)
                    result.success(mapOf("status" to "success", "data" to decrypted))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "sign" -> {
                try {
                    val param = call.arguments as? Map<String, Any>
                    val messageBytes = (param?.get("message") as? ByteArray) ?: byteArrayOf()
                    val signature = seCore.sign(messageBytes)
                    result.success(mapOf("status" to "success", "data" to signature))
                } catch (e: Exception) {
                    result.error("ERROR", e.localizedMessage, null)
                }
            }
            "verify" -> {
                try {
                    val param = call.arguments as? Map<String, Any>
                    val signatureText = param?.get("signature") as? String ?: ""
                    val plainText = param?.get("plainText") as? String ?: ""
                    val isValid = seCore.verify(plainText, signatureText)
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

    override fun onDetachedFromEngine(@NonNull binding: FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}