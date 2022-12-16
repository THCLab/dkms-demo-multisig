import 'package:flutter/foundation.dart';
import 'package:keri/keri.dart';


enum SelectedAction {
  multisigRequest,
  delegationRequest,
}
extension SelectedActionExtension on SelectedAction {
  String get name => describeEnum(this);
  Action get action {
    switch (this) {
      case SelectedAction.multisigRequest:
        return Action.MultisigRequest;
      case SelectedAction.delegationRequest:
        return Action.DelegationRequest;
      default:
        return Action.DelegationRequest;
    }
  }
}