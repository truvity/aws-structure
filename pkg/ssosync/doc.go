// Package ssosync deploys awslabs/ssosync, the Lambda that mirrors Google
// Workspace groups and their members into AWS IAM Identity Center over SCIM.
//
// What Deploy creates, in the provider's account and region (the one Identity
// Center lives in):
//
//   - the Lambda's role, with the basic execution policy and an inline policy
//     for sso:ListInstances and identitystore:*;
//   - a 14-day log group and the function itself (arm64, provided.al2023,
//     its configuration in environment variables: the Google credentials and
//     SCIM token as secrets);
//   - the EventBridge scheduler role and a schedule that invokes the function
//     every 15 minutes. There is no invocation on deploy: an invocation
//     resource runs only on create, and it failed deploys when SCIM was
//     unreachable at that moment, so the schedule does the sync.
//
// Everything that is an estate's own comes in through Args: the artifact's
// bucket and key, the SSM parameters that hold the SCIM endpoint and token, the
// Google credentials and the group query.
package ssosync
