import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_secure_enclave_platform_interface.dart';

/// An implementation of [FlutterSecureEnclavePlatform] that uses method channels.
class MethodChannelFlutterSecureEnclave extends FlutterSecureEnclavePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_secure_enclave');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
