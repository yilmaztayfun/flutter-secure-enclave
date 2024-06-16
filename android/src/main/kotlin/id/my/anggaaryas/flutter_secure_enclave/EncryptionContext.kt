package id.my.anggaaryas.flutter_secure_enclave

/*
 private lateinit var encryptionStrategy: EncryptionStrategy
 val apiLevel = Build.VERSION.SDK_INT
 encryptionStrategy = EncryptionContext.create(apiLevel)
 */
class EncryptionContext(private val apiLevel: Int) {
    companion object {
        fun create(apiLevel: Int): EncryptionStrategy {
            return if (apiLevel >= 18) {
                ModernEncryptionStrategy()
            } else {
                LegacyEncryptionStrategy()
            }
        }
    }
}