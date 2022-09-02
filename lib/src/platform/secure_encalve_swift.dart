import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../secure_enclave_base.dart';
import '../models/access_control_model.dart';
import '../models/result_model.dart';

class SecureEnclaveSwift extends SecureEnclaveBase {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('secure_enclave');

  /// Generetes a new private/public key pair
  @override
  Future<ResultModel<bool>> generateKeyPair(
      {required AccessControlModel accessControl}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'generateKeyPair',
      {
        "accessControl": accessControl.toJson(),
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as bool? ?? false;
      },
    );
  }

  /// remove key pair
  @override
  Future<ResultModel<bool>> removeKey(String tag) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'removeKey',
      {
        "tag": tag,
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as bool? ?? false;
      },
    );
  }

  /// get public key representation, this method will return Base64 encode
  /// you can share this public key to others device for sending encrypted data
  /// to your device
  @override
  Future<ResultModel<String?>> getPublicKey(
      {required String tag, String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'getPublicKey',
      {
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  /// encryption with secure enclave key pair
  @override
  Future<ResultModel<Uint8List?>> encrypt(
      {required String message, required String tag, String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'encrypt',
      {
        "message": message,
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as Uint8List?;
      },
    );
  }

  /// encryption with external public key
  @override
  Future<ResultModel<Uint8List?>> encryptWithPublicKey(
      {required String message, required String publicKey}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'encryptWithPublicKey',
      {
        "message": message,
        "publicKey": publicKey,
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as Uint8List?;
      },
    );
  }

  /// decryption with secure enclave key pair
  @override
  Future<ResultModel<String?>> decrypt(
      {required Uint8List message,
      required String tag,
      String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'decrypt',
      {
        "message": message,
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  /// check status is tag available or not
  @override
  Future<ResultModel<bool?>> getStatusSecKey(
      {required String tag, String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'getStatusSecKey',
      {
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as bool?;
      },
    );
  }

  /// generate signature from data
  @override
  Future<ResultModel<String?>> sign(
      {required Uint8List message,
      required String tag,
      String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'sign',
      {
        "message": message,
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  /// verify signature
  @override
  Future<ResultModel<bool?>> verify(
      {required String plainText,
      required String signature,
      required String tag,
      String? password}) async {
    final result = await methodChannel.invokeMethod<dynamic>(
      'verify',
      {
        "plainText": plainText,
        "signature": signature,
        "tag": tag,
        "password": password ?? '',
      },
    );

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from(result),
      decoder: (rawData) {
        return rawData as bool?;
      },
    );
  }
}
