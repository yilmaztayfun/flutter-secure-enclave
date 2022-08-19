// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'access_control.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AccessControl _$AccessControlFromJson(Map<String, dynamic> json) =>
    AccessControl(
      options: (json['options'] as List<dynamic>)
          .map((e) => $enumDecode(_$AccessControlOptionEnumMap, e))
          .toList(),
      tag: json['tag'] as String,
    );

Map<String, dynamic> _$AccessControlToJson(AccessControl instance) =>
    <String, dynamic>{
      'options':
          instance.options.map((e) => _$AccessControlOptionEnumMap[e]).toList(),
      'tag': instance.tag,
    };

const _$AccessControlOptionEnumMap = {
  AccessControlOption.devicePasscode: 'devicePasscode',
  AccessControlOption.biometryAny: 'biometryAny',
  AccessControlOption.biometryCurrentSet: 'biometryCurrentSet',
  AccessControlOption.userPresence: 'userPresence',
  AccessControlOption.watch: 'watch',
  AccessControlOption.privateKeyUsage: 'privateKeyUsage',
  AccessControlOption.applicationPassword: 'applicationPassword',
  AccessControlOption.or: 'or',
  AccessControlOption.and: 'and',
};

AppPasswordAccessControl _$AppPasswordAccessControlFromJson(
        Map<String, dynamic> json) =>
    AppPasswordAccessControl(
      password: json['password'] as String,
      tag: json['tag'] as String,
      options: (json['options'] as List<dynamic>)
          .map((e) => $enumDecode(_$AccessControlOptionEnumMap, e))
          .toList(),
    );

Map<String, dynamic> _$AppPasswordAccessControlToJson(
        AppPasswordAccessControl instance) =>
    <String, dynamic>{
      'options':
          instance.options.map((e) => _$AccessControlOptionEnumMap[e]).toList(),
      'tag': instance.tag,
      'password': instance.password,
    };
