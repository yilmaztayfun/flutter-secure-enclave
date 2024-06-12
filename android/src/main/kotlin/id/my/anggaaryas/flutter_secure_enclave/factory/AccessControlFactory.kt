package id.my.anggaaryas.flutter_secure_enclave.factory

import android.os.Build
import androidx.annotation.RequiresApi
import id.my.anggaaryas.flutter_secure_enclave.model.AccessControlParam

@RequiresApi(Build.VERSION_CODES.M)
class AccessControlFactory(private val value: Map<String, Any?>) {

    fun build(): AccessControlParam {
        return AccessControlParam(value)
    }
}
