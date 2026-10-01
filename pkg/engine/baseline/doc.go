// Package baseline deploys the per-account baseline controls of one AWS
// account as one Pulumi ComponentResource, truvity:aws-structure:AccountBaseline.
//
// What it creates, from the registry's Baseline:
//
//   - Baseline.EBSDefaultEncryption: one ebs.EncryptionByDefault in every
//     region of Baseline.Regions.
//   - Baseline.AccessAnalyzer: one ACCOUNT-type IAM Access Analyzer in every
//     region of Args.AnalyzerRegions, or of Baseline.Regions when that is empty.
//
// The caller supplies one AWS provider per region for the account: the
// component never falls back to a default provider, because a default would
// silently create the account's controls in whichever account the stack's
// default provider points at.
//
// What the component refuses, before registering anything: a missing account
// name, a missing provider for a region it needs, an empty or repeated region,
// a naming hook that returns an empty or repeated name, and a Baseline field
// this version does not implement (password policy, auditor role, boundaries)
// so that a registry asking for them is refused by name rather than ignored.
//
// No child is protected: these are account settings, and re-creating one is
// harmless.
//
// See docs/reference.md for the children, their names and their aliases.
package baseline
