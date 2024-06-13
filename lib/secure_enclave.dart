library secure_enclave;

import 'dart:typed_data';

import 'package:secure_enclave/secure_enclave_base.dart';
import 'package:secure_enclave/src/models/access_control_model.dart';
import 'package:secure_enclave/src/models/result_model.dart';

import 'src/platform/secure_encalve_swift.dart';

export 'src/constants/access_control_option.dart';
export 'src/models/access_control_model.dart';
export 'src/models/result_model.dart';
export 'src/models/error_model.dart';

class SecureEnclave implements SecureEnclaveBase {
  
  /// decryption with secure enclave key pair
  @override
  Future<ResultModel<String?>> decrypt(
      {required Uint8List message}) {
    return SecureEnclavePlatform.instance.decrypt(
      message: message
    );
  }

  /// encryption with secure enclave key pair
  @override
  Future<ResultModel<Uint8List?>> encrypt(
      {required String message}) {
    return SecureEnclavePlatform.instance.encrypt(
      message: message
    );
  }

  /// Generetes a new private/public key pair
  @override
  Future<ResultModel<bool>> generateKeyPair(
      {required AccessControlModel accessControl}) {
    return SecureEnclavePlatform.instance
        .generateKeyPair(accessControl: accessControl);
  }

  /// get public key representation, this method will return Base64 encode
  /// you can share this public key to others device for sending encrypted data
  /// to your device
  @override
  Future<ResultModel<String?>> getPublicKey() {
    return SecureEnclavePlatform.instance.getPublicKey();
  }

  /// remove key pair
  @override
  Future<ResultModel<bool>> removeKey() {
    return SecureEnclavePlatform.instance.removeKey();
  }

  /// generate signature from data
  @override
  Future<ResultModel<String?>> sign(
      {required Uint8List message}) {
    return SecureEnclavePlatform.instance.sign(
      message: message
    );
  }

  /// verify signature
  @override
  Future<ResultModel<bool?>> verify(
      {required String plainText,
      required String signature}) {
    return SecureEnclavePlatform.instance.verify(
      plainText: plainText,
      signature: signature
    );
  }

  /// check status is tag available or not
  @override
  Future<ResultModel<bool?>> isKeyCreated() {
    return SecureEnclavePlatform.instance.isKeyCreated();
  }
}
