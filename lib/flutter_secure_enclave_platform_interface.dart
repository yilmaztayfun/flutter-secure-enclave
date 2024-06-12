import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_secure_enclave_method_channel.dart';

abstract class FlutterSecureEnclavePlatform extends PlatformInterface {
  /// Constructs a FlutterSecureEnclavePlatform.
  FlutterSecureEnclavePlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterSecureEnclavePlatform _instance = MethodChannelFlutterSecureEnclave();

  /// The default instance of [FlutterSecureEnclavePlatform] to use.
  ///
  /// Defaults to [MethodChannelFlutterSecureEnclave].
  static FlutterSecureEnclavePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [FlutterSecureEnclavePlatform] when
  /// they register themselves.
  static set instance(FlutterSecureEnclavePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
