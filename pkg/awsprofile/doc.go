// Package awsprofile reaches AWS accounts by named profile, from inside a
// Pulumi program or from plain Go: an AWS SDK v2 config per profile (and
// region), the account id behind a profile, and a Pulumi AWS provider per
// profile (and region).
//
// Everything is cached per Manager, and safe for concurrent use. The account
// is whatever the profile in the shared AWS config resolves to: the package
// holds no profile, region or account of its own.
//
// Provider logical names are API, because a stack's state holds them:
//
//   - GetAWSProvider: "provider/aws/<profile>", region from the profile;
//   - GetAWSProviderWithRegion: "provider/aws/<profile>/<region>".
//
// GetAWSProviderWithRegion also shares its providers between Managers of one
// Pulumi program run (one *pulumi.Context): a program that composes several
// builders, each with its own Manager, registers each provider once instead of
// failing on a duplicate URN.
package awsprofile
