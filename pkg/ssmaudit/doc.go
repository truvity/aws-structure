// Package ssmaudit lists every SSM parameter in every account an AWS CLI
// config names and reports the names a caller-supplied predicate does not
// explain.
//
// The point is not that Parameter Store is empty: some things are read before
// any secret manager exists. The point is that everything left in it is there
// for a reason somebody wrote down. A parameter nobody can explain is debris,
// and debris in a secret store is indistinguishable from a secret nobody is
// watching.
//
// Read only. Every call is DescribeParameters; nothing is deleted, because
// what to do about an undeclared parameter is a decision, not a side effect of
// auditing.
//
// Mechanism only. Which paths are declared, which role suffix is the read-only
// one, which second region to sweep and what the closing hint says are inputs:
//
//   - [ReadAccounts] groups the config's read-only profiles by ACCOUNT.
//   - [Audit] visits each account and region with a [Lister] and returns a
//     [Result].
//   - [SSMLister] is the Lister over the real SSM client; [ListParameters]
//     pages any client that satisfies [DescribeParametersAPI].
//
// The Lister is an input, so the tests run against fakes and the package
// holds no profile, region or account.
package ssmaudit
