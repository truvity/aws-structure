// Package registry is the schema of an AWS organization's structure, and
// the strict loader and validator that stand between a registry file and
// anything that acts on it.
//
// One YAML file says what the organization IS: its organizational units,
// its accounts, its service control policies, its Identity Center
// (permission sets, groups, assignments) and the baseline every account
// carries. Nothing here talks to AWS; the engine and the preflight that
// come later consume a validated Registry.
//
// Loading is strict by construction. An unknown key is an error, not a
// silently dropped setting, and Validate reports every problem it finds in
// one pass, so a registry is fixed once rather than once per run. The
// refusals are listed in docs/reference.md and the reasoning is in
// docs/decisions/0001-shape.md and docs/decisions/0002-safety.md.
//
// The package holds no estate particulars: every name, id, address and
// policy document is the caller's, read from the caller's file.
package registry
