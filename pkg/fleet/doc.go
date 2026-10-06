// Package fleet runs the per-account engines over a set of member accounts:
// the organizational units and their accounts, the account baseline, the
// account IAM controls, CloudTrail and GuardDuty, each as one component per
// account (and region) in the stack, from a cross-account provider per account
// and region.
//
// The engines (pkg/engine/...) deploy ONE account; this package is the loop an
// organization's root stack writes around them: validate that the account set
// is the expected one, build the providers (each member is reached through its
// organization access role from the management account's profile), skip the
// accounts whose controls already exist elsewhere, and name each component
// "<control>-<account>[-<region>]". Those names are API.
//
// Nothing is deployed in the management account here except where a function
// says so. Every account name, id, region, profile, bucket name format and
// boundary name is a caller input.
package fleet
