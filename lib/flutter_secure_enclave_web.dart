// In order to *not* need this ignore, consider extracting the "web" version
// of your plugin as a separate package, instead of inlining it in the same
// package as the core of your plugin.
// ignore: avoid_web_libraries_in_flutter

import 'dart:typed_data';

import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:secure_enclave/src/models/access_control_model.dart';
import 'package:secure_enclave/src/models/result_model.dart';
import 'package:secure_enclave/src/platform/secure_encalve_swift.dart';


/// A web implementation of the FlutterSecureEnclavePlatform of the FlutterSecureEnclave plugin.
class FlutterSecureEnclaveWeb extends SecureEnclavePlatform {

 static void registerWith(Registrar registrar) {
    SecureEnclavePlatform.instance = FlutterSecureEnclaveWeb();
  }

  @override
  Future<ResultModel<String?>> decrypt({required Uint8List message, required String tag, String? password}) {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<Uint8List?>> encrypt({required String message, required String tag, String? password}) {
    // TODO: implement encrypt
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<Uint8List?>> encryptWithPublicKey({required String message, required String publicKey}) {
    // TODO: implement encryptWithPublicKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool>> generateKeyPair({required AccessControlModel accessControl}) {
    // TODO: implement generateKeyPair
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<String?>> getPublicKey({required String tag, String? password}) {
    // TODO: implement getPublicKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool?>> isKeyCreated({required String tag, String? password}) {
    // TODO: implement isKeyCreated
    throw UnimplementedError("Custom Error - isKeyCreated");
  }

  @override
  Future<ResultModel<bool>> removeKey(String tag) {
    // TODO: implement removeKey
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<String?>> sign({required Uint8List message, required String tag, String? password}) {
    // TODO: implement sign
    throw UnimplementedError();
  }

  @override
  Future<ResultModel<bool?>> verify({required String plainText, required String signature, required String tag, String? password}) {
    // TODO: implement verify
    throw UnimplementedError();
  }

}
