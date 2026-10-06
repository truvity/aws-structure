// Package alerting deploys the central security alerting of an AWS
// organization: one SNS topic per region in the management account, each with
// a topic policy, an HTTPS subscription to an alert receiver, and a Chatbot
// Slack channel configuration over all of them.
//
// What Security creates, per region in Args.Regions, with its own provider:
//
//   - the topic, and a topic policy that admits every principal of the
//     organization whose ARN is the "eventbridge-sns-<region>" role (the role
//     the guardduty component and NewImported publish as);
//   - an HTTPS subscription of the topic to the receiver's endpoint, with a
//     retry and throttle policy (DeliveryPolicy);
//   - in the primary region only, a heartbeat: an EventBridge schedule that
//     publishes a constant event to the topic every 15 minutes, and one extra
//     topic policy statement scoped to that one rule, because a service
//     principal carries no organization id.
//
// And once, in the primary region: the IAM role Chatbot assumes (bounded by a
// permissions boundary the caller names, with read-only access) and the Slack
// channel configuration subscribed to every topic.
//
// It returns the topic ARNs by region, for the guardduty rules to publish to.
// The package never writes an organization id, a Slack id, an endpoint, a
// topic name or a boundary name of its own: all of them are inputs.
package alerting
