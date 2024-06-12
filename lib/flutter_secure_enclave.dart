
import 'flutter_secure_enclave_platform_interface.dart';

class FlutterSecureEnclave {
  Future<String?> getPlatformVersion() {
    return FlutterSecureEnclavePlatform.instance.getPlatformVersion();
  }
}
