import 'package:json_annotation/json_annotation.dart';

import '../constants/access_control_option.dart';

part 'access_control_model.g.dart';

// @JsonSerializable()
// class AccessControlModel {
//   final List<AccessControlOption> options;
//   final String tag;

//   AccessControlModel._({required this.options, required this.tag});

//   factory AccessControlModel(
//       {required List<AccessControlOption> options, required String tag}) {
//     return AccessControlModel._(options: options, tag: tag);
//   }

//   factory AccessControlModel.fromJson(Map<String, dynamic> json) =>
//       _$AccessControlModelFromJson(json);

//   Map<String, dynamic> toJson() => _$AccessControlModelToJson(this);
// }

@JsonSerializable()
class AccessControlModel {
  final List<AccessControlOption> options;

  AccessControlModel._({
    required this.options
  });

  factory AccessControlModel({
    required List<AccessControlOption> options,
  }) {
    return AccessControlModel._(options: options);
  }

  factory AccessControlModel.fromJson(Map<String, dynamic> json) =>
      _$AccessControlModelFromJson(json);

  Map<String, dynamic> toJson() => _$AccessControlModelToJson(this);
}
