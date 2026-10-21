package cdkbootstrap

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// StackPrefix starts the name of every bootstrap stack: "CDKToolkit-<qualifier>".
const StackPrefix = "CDKToolkit-"

// AdministratorAccess is the managed policy the CloudFormation execution role
// carries when a Bootstrap names none. The role's permissions boundary
// (Bootstrap.DeployBoundary) caps it.
const AdministratorAccess = "AdministratorAccess"

var (
	qualifierRE = regexp.MustCompile(`^[a-z0-9]{1,10}$`)
	accountRE   = regexp.MustCompile(`^[0-9]{12}$`)
	regionRE    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	boundaryRE  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,128}$`)
)

// Bootstrap is the bootstrap of one CDK app (one qualifier) in a set of
// accounts and regions.
type Bootstrap struct {
	// Qualifier is the app's CDK qualifier, the one it sets in its
	// DefaultStackSynthesizer: 1 to 10 lowercase letters and digits. The
	// bootstrap's roles and buckets are named "cdk-<qualifier>-*". Required.
	Qualifier string
	// DeployBoundary is the name of the permissions boundary policy that every
	// role of the bootstrap carries, in each account: the app's deploy
	// boundary. The policy must exist in the account before the stack is
	// created. Required.
	DeployBoundary string
	// Accounts are the names of the accounts the bootstrap is deployed to.
	// Required.
	Accounts []string
	// Regions are the regions it is deployed to in each account. Required.
	Regions []string
	// ExecutionPolicies are the ARNs of the managed policies the
	// CloudFormation execution role carries. Empty means AdministratorAccess,
	// which DeployBoundary caps.
	ExecutionPolicies []string
	// TrustedAccounts are the ids of other accounts whose CDK CLI may deploy
	// through this bootstrap. Empty means the account itself alone.
	TrustedAccounts []string
}

// StackName is the name of the CloudFormation stack of the bootstrap.
func (b Bootstrap) StackName() string { return StackPrefix + b.Qualifier }

// Parameters returns the stack parameters of the bootstrap in a partition.
func (b Bootstrap) Parameters(partition string) map[string]string {
	policies := b.ExecutionPolicies
	if len(policies) == 0 {
		policies = []string{fmt.Sprintf("arn:%s:iam::aws:policy/%s", partition, AdministratorAccess)}
	}

	return map[string]string{
		"Qualifier":                       b.Qualifier,
		"InputPermissionsBoundary":        b.DeployBoundary,
		"CloudFormationExecutionPolicies": strings.Join(policies, ","),
		"TrustedAccounts":                 strings.Join(b.TrustedAccounts, ","),
	}
}

// Validate reports every problem with b at once, or returns nil. It does not
// know whether DeployBoundary exists: pkg/boundary's Spec.Validate checks that.
func (b Bootstrap) Validate() error {
	var errs []error

	if !qualifierRE.MatchString(b.Qualifier) {
		errs = append(errs, fmt.Errorf("qualifier %q is not 1 to 10 lowercase letters and digits", b.Qualifier))
	}

	if !boundaryRE.MatchString(b.DeployBoundary) {
		errs = append(errs, fmt.Errorf("%s: DeployBoundary %q is not a policy name", b.label(), b.DeployBoundary))
	}

	errs = append(errs, b.checkList("Accounts", b.Accounts, nil)...)
	errs = append(errs, b.checkList("Regions", b.Regions, regionRE)...)
	errs = append(errs, b.checkList("TrustedAccounts", b.TrustedAccounts, accountRE)...)

	if len(b.Accounts) == 0 {
		errs = append(errs, fmt.Errorf("%s: Accounts is empty", b.label()))
	}

	if len(b.Regions) == 0 {
		errs = append(errs, fmt.Errorf("%s: Regions is empty", b.label()))
	}

	seen := map[string]bool{}

	for _, p := range b.ExecutionPolicies {
		switch {
		case !strings.HasPrefix(p, "arn:") || strings.ContainsAny(p, ", \t"):
			errs = append(errs, fmt.Errorf("%s: ExecutionPolicies entry %q is not a policy ARN", b.label(), p))
		case seen[p]:
			errs = append(errs, fmt.Errorf("%s: ExecutionPolicies lists %q twice", b.label(), p))
		}

		seen[p] = true
	}

	return errors.Join(errs...)
}

func (b Bootstrap) label() string { return "bootstrap " + b.Qualifier }

// checkList refuses an empty or repeated entry, and one that does not match re
// when it is set.
func (b Bootstrap) checkList(field string, list []string, re *regexp.Regexp) []error {
	var errs []error

	seen := map[string]bool{}

	for _, v := range list {
		switch {
		case v == "":
			errs = append(errs, fmt.Errorf("%s: %s has an empty entry", b.label(), field))
		case re != nil && !re.MatchString(v):
			errs = append(errs, fmt.Errorf("%s: %s entry %q is malformed", b.label(), field, v))
		case seen[v]:
			errs = append(errs, fmt.Errorf("%s: %s lists %q twice", b.label(), field, v))
		}

		seen[v] = true
	}

	return errs
}

// Validate checks every bootstrap on its own and the set as a whole: no two
// bootstraps may claim one (qualifier, account, region), since they would be
// the same stack and the same roles.
func Validate(all []Bootstrap) error {
	var errs []error

	claimed := map[[3]string]int{}

	for i := range all {
		b := &all[i]

		if err := b.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("bootstraps[%d]: %w", i, err))
		}

		for _, a := range b.Accounts {
			for _, r := range b.Regions {
				key := [3]string{b.Qualifier, a, r}

				if prev, dup := claimed[key]; dup && prev != i {
					errs = append(errs, fmt.Errorf("bootstraps[%d] and bootstraps[%d] both bootstrap qualifier %q in %s/%s", prev, i, b.Qualifier, a, r))

					continue
				}

				claimed[key] = i
			}
		}
	}

	return errors.Join(errs...)
}

// Accounts returns the names of every account the bootstraps name, sorted.
func Accounts(all []Bootstrap) []string {
	var out []string

	for i := range all {
		for _, a := range all[i].Accounts {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}

	slices.Sort(out)

	return out
}
