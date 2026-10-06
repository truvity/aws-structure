// Package cost deploys the cost alerting of an AWS organization's payer
// account: monthly budgets, Cost Anomaly Detection and the cost category that
// splits one account, all alerting through two SNS topics that each have one
// HTTPS subscription to an alert receiver. Nothing here sends email.
//
// What Deploy creates, in the payer account:
//
//   - a provider for the cost region, and two plain topics (budgets and
//     anomalies; no SSE: Budgets refuses a topic encrypted with a key whose
//     policy does not grant it, and these carry no secret) with a policy that
//     lets exactly one AWS service principal publish, and their subscriptions;
//   - one monthly cost budget for the whole organization and one per linked
//     account, each notifying at 100% forecast and 80% and 100% actual;
//   - the AWS-created services anomaly monitor, adopted (imported, protected,
//     retained), an optional custom monitor per account, and one immediate
//     anomaly subscription over all of them above a threshold;
//   - optionally Compute Optimizer enrollment, the cost allocation tags the
//     category reads, and the cost category itself (see Category).
//
// Everything that is an estate's own comes in through Args: the payer account,
// the budgets and their accounts, the monitor to adopt, the category's rules,
// the topic names and the receiver's endpoint.
package cost
