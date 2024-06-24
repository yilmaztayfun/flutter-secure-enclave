# Secure Enclave

Apple, Android and Web Secure Enclave implementaton for Flutter

# What is a Secure Enclave? 👮
*The Secure Enclave is a dedicated secure subsystem integrated into Apple systems on chip (SoCs). The Secure Enclave is isolated from the main processor to provide an extra layer of security and is designed to keep sensitive user data secure even when the Application Processor kernel becomes compromised.* https://support.apple.com/en-ie/guide/security/sec59b0b31ff/web

[![](https://help.apple.com/assets/6026E7D7748ADA67B165542D/6026E7DA748ADA67B1655435/en_GB/388d8f7e1d4dd8c22d85c87ca9d01622.png)](https://help.apple.com/assets/6026E7D7748ADA67B165542D/6026E7DA748ADA67B1655435/en_GB/388d8f7e1d4dd8c22d85c87ca9d01622.png)

# Feature Set ✨

✅ Check tag status 

✅ Generate Key Pair 

✅ Get Public Key

✅ Encrypt

✅ Decrypt

✅ Sign

✅ Verify

# How to Use 🚀

📈 **Check tag status :**
```dart
final _secureEnclavePlugin = SecureEnclave();
final bool status = (await _secureEnclavePlugin.isKeyCreated(tag: 'kota')).value;
```

🔑 **Generate Key Pair :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.generateKeyPair(
    accessControl: AccessControlModel(
      options: [
      ],
      tag: 'kota',
    ),
);

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value);
}
 
```

📢 **Get Public Key :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.getPublicKey(tag: 'kota');

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value);
}
 
```

🔒 **Encrypt :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.encrypt(
    message: 'hello jakarta',
    tag: 'kota'
);

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value); // Uint8List
}
```

🔓 **Decrypt :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.decrypt(
    message: Uint8List.fromList(hex.decode('iasjfoiaj2EL3EL')), // hex => Uint8List
    tag: 'kota'
);

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value);
}
```

🔏 **Sign :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.sign(
    message: Uint8List.fromList('hello jakarta'.codeUnits), // String => Uint8List
    tag: 'kota'
);

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value);
}
```

✅ **Verify :**
```dart
final _secureEnclavePlugin = SecureEnclave();

ResultModel res = await _secureEnclavePlugin.verify(
	plainText: 'hello jakarta',
    signature: 'fDrPlGl48R8DPCGNTsAticYfx3RoWPKxEHQ2pHWrBDGk887UwWYGVTSSUj6LciietChBULEs ',
    tag: 'kota'
);

if (res.error != null) {
	print(res.error!.desc.toString());
} else {
	print(res.value);
}
```

## Rerefences
- https://github.com/anggaaryas/flutter-secure-enclave