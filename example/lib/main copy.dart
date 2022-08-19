// import 'dart:convert';
// import 'dart:typed_data';

// import 'package:flutter/material.dart';
// import 'dart:async';

// import 'package:flutter/services.dart';
// import 'package:secure_enclave/secure_enclave.dart';
// import 'package:secure_enclave/src/model/method_result.dart';

// final _messangerKey = GlobalKey<ScaffoldMessengerState>();

// void main() {
//   runApp(const MyApp());
// }

// class MyApp extends StatefulWidget {
//   const MyApp({Key? key}) : super(key: key);

//   @override
//   State<MyApp> createState() => _MyAppState();
// }

// class _MyAppState extends State<MyApp> {
//   final _secureEnclavePlugin = SecureEnclave();
//   final String tag = "keychain-test.privateKey";
//   final String tagBiometric = "keychain-test.privateKey.biometric";
//   final String tagPassword = "keychain-test.privateKey.password";
//   final String tagPasswordBiometric = "keychain-test.privateKey.password.biometric";

//   bool _isRequiresBiometric = false;
//   bool isUsingAppPassword = false;
//   String publicKey = "";

//   TextEditingController input = TextEditingController();
//   TextEditingController inputPassword = TextEditingController();

//   Uint8List encrypted = Uint8List(0);
//   Uint8List encryptedWithPublicKey = Uint8List(0);
//   String decrypted = "";

//   @override
//   void initState() {
//     super.initState();
//   }

//   void encrypt(String message) {
//     _secureEnclavePlugin
//         .encrypt(
//             message: message,
//             tag: getTag())
//         .then((result) => setState(() {
//               if (result.error == null) {
//                 encrypted = result.value ?? Uint8List(0);
//               } else {
//                 showError(result);
//               }
//             }));
//   }

//   void showError(MethodResult result) {
//     final error = result.error!;
//     _messangerKey.currentState?.showSnackBar(SnackBar(
//         content:
//             Text('code = ${error.code}  |  desc = ${error.desc}')));
//   }

//   void createKey(){
//     _secureEnclavePlugin.createKey(
//         accessControl: isUsingAppPassword? AppPasswordAccessControl(
//             password: inputPassword.text,
//             tag: getTag(),
//             options: getOption())
//         : AccessControl(options: getOption(), tag: getTag())
//     ).then((result){
//       if(result.error == null){
//         _messangerKey.currentState?.showSnackBar(SnackBar(
//             content:
//             Text('success create key = ${getTag()}')));
//       } else {
//         showError(result);
//       }
//     });
//   }

//   void checkKey(){
//     _secureEnclavePlugin.checkKey(getTag()).then((value){
//       _messangerKey.currentState?.showSnackBar(SnackBar(
//           content:
//           Text('tag = ${getTag()}  |   $value')));
//     });
//   }

//   List<AccessControlOption> getOption() => _isRequiresBiometric? SecureEnclave.defaultRequiredAuthForAccessControlOption : SecureEnclave.defaulAccessControlOption;

//   void encryptWithPublicKey(String message) {
//     _secureEnclavePlugin
//         .encryptWithPublicKey(
//             message: message,
//             publicKeyString: publicKey)
//         .then((result) => setState(() {
//               if (result.error == null) {
//                 encryptedWithPublicKey = result.value ?? Uint8List(0);
//               } else {
//                 showError(result);
//               }
//             }));
//   }

//   void decrypt(Uint8List message, String? password) {
//     _secureEnclavePlugin
//         .decrypt(
//             message: message,
//           tag:   getTag(),
//           password: password)
//         .then((result) => setState(() {
//               if (result.error == null) {
//                 decrypted = result.value ?? "";
//               } else {
//                 showError(result);
//               }
//             }));
//   }

//   String getTag() => isUsingAppPassword ? _isRequiresBiometric ? tagPasswordBiometric : tagPassword : _isRequiresBiometric? tagBiometric: tag;

//   void getPublicKey() {
//     _secureEnclavePlugin
//         .getPublicKey(tag: getTag())
//         .then((result) {
//       if (result.error == null) {
//         publicKey = result.value ?? "";
//         setState(() {});
//       } else {
//         showError(result);
//       }
//     });
//   }

//   Future<void> removeKey() async {
//     await _secureEnclavePlugin.removeKey(tag).then((result) {
//       print("delete $tag = ${result.value}");
//     });
//     await _secureEnclavePlugin.removeKey(tagBiometric).then((result) {
//       print("delete $tagBiometric = ${result.value}");
//     });
//     await _secureEnclavePlugin.removeKey(tagPasswordBiometric).then((result) {
//       print("delete $tagPasswordBiometric = ${result.value}");
//     });
//     await _secureEnclavePlugin.removeKey(tagPassword).then((result) {
//       print("delete $tagPassword = ${result.value}");
//     });
//   }

//   void cobaError() {
//     _secureEnclavePlugin.cobaError().then((result) {
//       if (result.error == null) {
//         print("Kok Sukses???");
//       } else {
//         final error = result.error!;
//         _messangerKey.currentState?.showSnackBar(SnackBar(
//             content: Text('code = ${error.code}  |  desc = ${error.desc}')));
//       }
//     });
//   }

//   @override
//   Widget build(BuildContext context) {
//     return MaterialApp(
//       scaffoldMessengerKey: _messangerKey,
//       home: Scaffold(
//         appBar: AppBar(
//           title: const Text('Plugin example app'),
//         ),
//         body: ListView(
//           children: [
//             TextField(
//               controller: input,
//             ),
//             isUsingAppPassword? TextField(
//               controller: inputPassword,
//             ): Container(),
//             Row(
//               children: [
//                 const Text("Biometric"),
//                 const SizedBox(
//                   width: 10,
//                 ),
//                 Switch(
//                     value: _isRequiresBiometric,
//                     onChanged: (value) {
//                       setState(() {
//                         _isRequiresBiometric = value;
//                         encrypted = Uint8List(0);
//                         decrypted = "";
//                       });
//                     }),
//               ],
//             ),
//             Row(
//               children: [
//                 const Text("App Password"),
//                 const SizedBox(
//                   width: 10,
//                 ),
//                 Switch(
//                     value: isUsingAppPassword,
//                     onChanged: (value) {
//                       setState(() {
//                         isUsingAppPassword = value;
//                         encrypted = Uint8List(0);
//                         decrypted = "";
//                       });
//                     }),
//               ],
//             ),
//             TextButton(
//                 onPressed: () {
//                   checkKey();
//                 },
//                 child: Text("check Key")),
//             TextButton(
//                 onPressed: () {
//                   createKey();
//                 },
//                 child: Text("create Key!")),
//             TextButton(
//                 onPressed: () {
//                   encrypt(input.text);
//                   // input.clear();
//                 },
//                 child: Text("encrypt!")),
//             Text(encrypted.toString()),
//             TextButton(
//                 onPressed: () {
//                   decrypt(encrypted, isUsingAppPassword? inputPassword.text : null);
//                 },
//                 child: Text("decrypt!")),
//             Text(decrypted),
//             Divider(),
//             TextButton(
//                 onPressed: () {
//                   removeKey();
//                 },
//                 child: Text("reset key")),
//             Divider(),
//             TextButton(
//                 onPressed: () {
//                   cobaError();
//                 },
//                 child: Text("coba Error")),
//             Divider(),
//             Text(publicKey),
//             TextButton(
//                 onPressed: () {
//                   getPublicKey();
//                 },
//                 child: Text("get public key")),
//             TextButton(
//                 onPressed: () {
//                   encryptWithPublicKey(input.text);
//                 },
//                 child: Text("encrypt with public key")),
//             Text(encryptedWithPublicKey.toString()),
//             TextButton(
//                 onPressed: () {
//                   decrypted = "";
//                   decrypt(encryptedWithPublicKey, isUsingAppPassword? inputPassword.text: null);
//                 },
//                 child: Text("decrypt from encryptedWithPublicKey")),
//           ],
//         ),
//       ),
//     );
//   }
// }
