// In order to *not* need this ignore, consider extracting the "web" version
// of your plugin as a separate package, instead of inlining it in the same
// package as the core of your plugin.
// ignore: avoid_web_libraries_in_flutter

import 'dart:math';
import 'dart:typed_data';
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_bit_string.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_null.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:secure_enclave/src/models/access_control_model.dart';
import 'package:secure_enclave/src/models/result_model.dart';
import 'package:secure_enclave/src/platform/secure_encalve_swift.dart';
import 'package:pointycastle/export.dart';

/// A web implementation of the FlutterSecureEnclavePlatform of the FlutterSecureEnclave plugin.
class FlutterSecureEnclaveWeb extends SecureEnclavePlatform {
 final FlutterSecureStorage _storage =  FlutterSecureStorage();
 static const String publicKeyStorageKey = 'publicKey';
 static const String privateKeyStorageKey = 'privateKey';
 static void registerWith(Registrar registrar) {
    SecureEnclavePlatform.instance = FlutterSecureEnclaveWeb();
  }

  @override
  Future<ResultModel<String?>> decrypt({required Uint8List message}) async {
    final privateKey = await getPrivateKey();
    final decryptor = OAEPEncoding(RSAEngine())..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final result =  utf8.decode(_processInBlocks(decryptor, message));

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": result}),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  @override
  Future<ResultModel<Uint8List?>> encrypt({required String message}) async {
    final publicKey = await getPublicKeyInernal();
    final encryptor = OAEPEncoding(RSAEngine())..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    final result = _processInBlocks(encryptor, Uint8List.fromList(utf8.encode(message)));

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": result}),
      decoder: (rawData) {
        return rawData as Uint8List?;
      },
    );
  }

  @override
  Future<ResultModel<bool>> generateKeyPair({required AccessControlModel accessControl}) async {
    var keyParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64);
    var secureRandom = FortunaRandom();

    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    var rngParams = ParametersWithRandom(keyParams, secureRandom);
    var keyGenerator = RSAKeyGenerator();
    keyGenerator.init(rngParams);

    var pair = keyGenerator.generateKeyPair();
    var publicKey = pair.publicKey as RSAPublicKey;
    var privateKey = pair.privateKey as RSAPrivateKey;

    // Save keys to storage
    await _storage.write(key: publicKeyStorageKey, value: encodePublicKeyToPem(publicKey));
    await _storage.write(key: privateKeyStorageKey, value: encodePrivateKeyToPem(privateKey));

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": true}),
      decoder: (rawData) {
        return rawData as bool;
      },
    ); 
  }

  @override
  Future<ResultModel<String?>> getPublicKey() async {
     var publicKey = await getPublicKeyInernal();
     return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": publicKey}),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  Future<RSAPrivateKey> getPrivateKey() async {
    var privateKeyPem = await _storage.read(key: privateKeyStorageKey);
    return decodePrivateKeyFromPem(privateKeyPem!);
  }

  Future<RSAPublicKey> getPublicKeyInernal() async {
      var publicKeyPem = await _storage.read(key: publicKeyStorageKey);
      return decodePublicKeyFromPem(publicKeyPem!);
  }

  @override
  Future<ResultModel<bool?>> isKeyCreated() async {
    try {
      var publicKey = await _storage.containsKey(key: publicKeyStorageKey);
      var privateKey = await _storage.containsKey(key: publicKeyStorageKey);

      var result = (publicKey && privateKey);
      return ResultModel.fromMap(
        map: Map<String, dynamic>.from({"data": result}),
        decoder: (rawData) {
          return rawData as bool;
        },
      );
    } catch (e) {
      rethrow;
    }
    
  }

  @override
  Future<ResultModel<bool>> removeKey() async {
    await _storage.delete(key: publicKeyStorageKey);
    await _storage.delete(key: privateKeyStorageKey);
    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": true}),
      decoder: (rawData) {
        return rawData as bool;
      },
    );
  }

  @override
  Future<ResultModel<String?>> sign({required Uint8List message}) async {
    final privateKey = await getPrivateKey();
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    var result = signer.generateSignature(message).bytes;

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": base64Encode(result)}),
      decoder: (rawData) {
        return rawData as String?;
      },
    );
  }

  @override
  Future<ResultModel<bool?>> verify({required String plainText, required String signature}) async {
    final publicKey = await getPublicKeyInernal();
    final verifier = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));

    bool result = false;
    try {
      result = verifier.verifySignature(Uint8List.fromList(utf8.encode(plainText)), RSASignature(base64Decode(signature)));
    } catch (e) {
      result = false;
    }

    return ResultModel.fromMap(
      map: Map<String, dynamic>.from({"data": result}),
      decoder: (rawData) {
        return rawData as bool;
      },
    );
  }

  String encodePublicKeyToPem(RSAPublicKey publicKey) {
    var algorithmSequence = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromName('rsaEncryption'))
      ..add(ASN1Null());

    var publicKeySequence = ASN1Sequence()
      ..add(ASN1Integer(publicKey.modulus!))
      ..add(ASN1Integer(publicKey.exponent!));

    var publicKeyBitString = ASN1BitString(stringValues: publicKeySequence.encode());

    var topLevelSequence = ASN1Sequence()
      ..add(algorithmSequence)
      ..add(publicKeyBitString);

    return _pemEncode(topLevelSequence.encode(), 'PUBLIC KEY');
  }

  String encodePrivateKeyToPem(RSAPrivateKey privateKey) {
    var version = ASN1Integer(BigInt.zero);
    var modulus = ASN1Integer(privateKey.n!);
    var publicExponent = ASN1Integer(privateKey.publicExponent!);
    var privateExponent = ASN1Integer(privateKey.exponent!);
    var p = ASN1Integer(privateKey.p!);
    var q = ASN1Integer(privateKey.q!);
    var dP = ASN1Integer(privateKey.d! % (privateKey.p! - BigInt.one));
    var dQ = ASN1Integer(privateKey.d! % (privateKey.q! - BigInt.one));
    var qInv = ASN1Integer(privateKey.q!.modInverse(privateKey.p!));

    var privateKeySequence = ASN1Sequence()
      ..add(version)
      ..add(modulus)
      ..add(publicExponent)
      ..add(privateExponent)
      ..add(p)
      ..add(q)
      ..add(dP)
      ..add(dQ)
      ..add(qInv);

    return _pemEncode(privateKeySequence.encode(), 'RSA PRIVATE KEY');
  }

  RSAPublicKey decodePublicKeyFromPem(String pem) {
    var bytes = _pemDecode(pem);
    var asn1Parser = ASN1Parser(bytes);
    
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;
    var publicKeyAsn = ASN1Parser(Uint8List.fromList(publicKeyBitString.stringValues!));
    ASN1Sequence publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;

    var modulus = publicKeySeq.elements![0] as ASN1Integer;
    var exponent = publicKeySeq.elements![1] as ASN1Integer;

    return RSAPublicKey(modulus.integer!, exponent.integer!);
  }

  RSAPrivateKey decodePrivateKeyFromPem(String pem) {
    var bytes = _pemDecode(pem);
    var asn1Parser = ASN1Parser(bytes);
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus = topLevelSeq.elements![1] as ASN1Integer;
    // var publicExponent = topLevelSeq.elements![2] as ASN1Integer;
    var privateExponent = topLevelSeq.elements![3] as ASN1Integer;
    var p = topLevelSeq.elements![4] as ASN1Integer;
    var q = topLevelSeq.elements![5] as ASN1Integer;

    return RSAPrivateKey(
      modulus.integer!,
      privateExponent.integer!,
      p.integer!,
      q.integer!
    );
  }

  Uint8List _pemDecode(String pem) {
    var startsWith = pem.indexOf('-----BEGIN');
    var endsWith = pem.indexOf('-----END');
    var base64String = pem.substring(startsWith, endsWith).split('\n').sublist(1).join();
    return base64.decode(base64String);
     
  }

  String _pemEncode(Uint8List bytes, String label) {
    var base64String = base64.encode(bytes);
    var chunks = <String>[];
    for (var i = 0; i < base64String.length; i += 64) {
      var end = (i + 64 < base64String.length) ? i + 64 : base64String.length;
      chunks.add(base64String.substring(i, end));
    }
    var pemString = '-----BEGIN $label-----\n${chunks.join('\n')}\n-----END $label-----';
    return pemString;
  }

  Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
    int inputOffset = 0;
    int inputBlockSize = engine.inputBlockSize;
    int outputBlockSize = engine.outputBlockSize;
    var output = Uint8List(0);

    while (inputOffset < input.length) {
      int chunkSize = (inputOffset + inputBlockSize) > input.length ? input.length - inputOffset : inputBlockSize;
      var chunk = Uint8List.view(input.buffer, inputOffset, chunkSize);
      var processedChunk = engine.process(chunk);
      output = Uint8List.fromList(output + processedChunk);
      inputOffset += chunkSize;
    }

    return output;
  }

}