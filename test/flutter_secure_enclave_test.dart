import 'package:flutter_test/flutter_test.dart';
import 'package:secure_enclave/flutter_secure_enclave.dart';
import 'package:secure_enclave/flutter_secure_enclave_platform_interface.dart';
import 'package:secure_enclave/flutter_secure_enclave_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterSecureEnclavePlatform
    with MockPlatformInterfaceMixin
    implements FlutterSecureEnclavePlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final FlutterSecureEnclavePlatform initialPlatform = FlutterSecureEnclavePlatform.instance;

  test('$MethodChannelFlutterSecureEnclave is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterSecureEnclave>());
  });

  test('getPlatformVersion', () async {
    FlutterSecureEnclave flutterSecureEnclavePlugin = FlutterSecureEnclave();
    MockFlutterSecureEnclavePlatform fakePlatform = MockFlutterSecureEnclavePlatform();
    FlutterSecureEnclavePlatform.instance = fakePlatform;

    expect(await flutterSecureEnclavePlugin.getPlatformVersion(), '42');
  });
}
