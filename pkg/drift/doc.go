// Package drift reads an organization back from AWS and compares it with the
// registry: what exists that nobody declared (an account made by hand, an
// assignment granted in the console), what is declared and gone, and what
// moved. It also builds the access-roles map: for every account, the IAM role
// Identity Center provisioned for each permission set, which consumers need
// for trust policies, EKS access entries and key policies.
//
// Read only. Nothing here writes to AWS; every call is a List or Describe.
//
//   - Read walks the organization (root, OUs, accounts, the service control
//     policies attached to each) and Identity Center (permission sets,
//     groups, users, assignments) into a Live.
//   - Compare(registry, live) returns the findings.
//   - AccessRoles lists the reserved SSO roles of each account and
//     RenderAccessRoles writes them as YAML.
//
// The AWS clients are inputs (small interfaces the SDK clients satisfy), so
// the package holds no profile, region or account, and the tests run against
// fakes.
package drift
