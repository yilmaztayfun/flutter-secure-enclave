package id.my.anggaaryas.flutter_secure_enclave

import android.security.keystore.KeyGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

@RequiresApi(Build.VERSION_CODES.M)
class AccessControlParam(value: Map<String, Any>) {
    val password: String?
    val tag: String
    var option: Int = 0

    init {
        val password = value["password"] as? String
        this.password = password
        this.tag = value["tag"] as String
        buildOption(value["options"] as List<String>)
    }

    private fun buildOption(optionsParam: List<String>) {
        for (opt in optionsParam) {
            when (opt) {
                "devicePasscode" -> option = option or KeyGenParameterSpec.PURPOSE_ENCRYPT
                "biometryAny" -> option = option or KeyGenParameterSpec.PURPOSE_DECRYPT
                "biometryCurrentSet" -> option = option or KeyGenParameterSpec.PURPOSE_SIGN
                "userPresence" -> option = option or KeyGenParameterSpec.PURPOSE_VERIFY
                "privateKeyUsage" -> option = option or RSAKeyGenParameterSpec.F4
                "applicationPassword" -> option = option or KeyGenParameterSpec.PURPOSE_WRAP_KEY
                "or" -> option = option or KeyGenParameterSpec.PURPOSE_UNWRAP_KEY
                "and" -> option = option or KeyGenParameterSpec.PURPOSE_WRAP_KEY
            }
        }
    }
}
