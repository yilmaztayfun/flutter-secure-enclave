import 'dart:typed_data';

import 'src/models/access_control_model.dart';
import 'src/models/result_model.dart';

abstract class SecureEnclaveBase {
  Future<ResultModel<bool>> generateKeyPair({
    required AccessControlModel accessControl,
  });

  Future<ResultModel<bool>> removeKey();

  Future<ResultModel<String?>> getPublicKey();

  Future<ResultModel<bool?>> isKeyCreated();

  Future<ResultModel<Uint8List?>> encrypt({
    required String message
  });

  Future<ResultModel<String?>> decrypt({
    required Uint8List message
  });

  Future<ResultModel<String?>> sign({
    required Uint8List message
  });

  Future<ResultModel<bool?>> verify({
    required String plainText,
    required String signature
  });
}

//
