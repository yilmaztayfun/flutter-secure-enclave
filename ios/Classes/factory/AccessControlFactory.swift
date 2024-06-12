import android.os.Build
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.M)
class AccessControlFactory(private val value: Map<String, Any>) {
    fun build(): AccessControlParam {
        return AccessControlParam(value)
    }
}
