// Package guardduty deploys GuardDuty finding alerting for one AWS account in
// one region as one Pulumi ComponentResource,
// truvity:aws-structure:AccountRegionGuardDuty.
//
// What it creates, for the account and region it is given:
//
//   - a GuardDuty detector, enabled;
//   - the role EventBridge assumes to publish, with a trust policy for
//     events.amazonaws.com and the permissions boundary the caller names;
//   - that role's inline policy, which allows sns:Publish on one topic;
//   - an EventBridge rule matching GuardDuty findings;
//   - the rule's target, which sends them to the topic with the role.
//
// The topic usually lives in another account (a central alerting account), and
// its policy is the caller's: the component only publishes to the ARN it is
// given. The component never writes an ARN or an account id itself. The topic
// ARN and the permissions boundary ARN are caller inputs.
//
// The component is per account and per region because a GuardDuty detector,
// an EventBridge rule and a role's policy are all regional objects, each
// region needs its own provider, and the topic is a per-region input. It does
// not do anything at the organization level: no delegated administrator, no
// organization configuration, no member accounts, no protection plans and no
// publishing destinations. The code this component was extracted from creates
// none of them, so neither does the component.
//
// The caller supplies the AWS provider: the component never falls back to a
// default provider, which would silently create the detector in whichever
// account the stack's default provider points at.
//
// What the component refuses, before registering anything and all at once: a
// missing account name, region, provider, topic ARN or permissions boundary,
// and a naming hook that returns an empty or repeated name.
//
// No child is protected and none is retained on delete: that is what the
// resources this component was extracted from carried, and the component adds
// nothing to it.
//
// See docs/reference.md for the children, their names and their aliases.
package guardduty
