package ssmaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"gopkg.in/ini.v1"
)

type (
	// Account is one AWS account in one region, with every read-only profile
	// that might reach it.
	Account struct {
		// Profiles are tried in order until one can list. An account is
		// reachable through several SSO roles with different names, and the
		// operator holds some of them and not others, so which profile works
		// is discovered, not declared.
		Profiles []string
		ID       string
		Region   string
	}

	// Finding is one parameter nothing explains.
	Finding struct {
		// Account is "<id> <region> via <profile>".
		Account string
		Name    string
	}

	// Skipped is an account and region no profile could list.
	Skipped struct {
		Account Account
		Err     error
	}

	// Result is what an audit found.
	Result struct {
		// Declared counts the parameters the predicate explained.
		Declared   int
		Undeclared []Finding
		Skipped    []Skipped
	}

	// Lister returns the names of every parameter the profile sees in the
	// region.
	Lister func(ctx context.Context, profile, region string) ([]string, error)

	// Config is what Audit takes.
	Config struct {
		// ConfigFile is the AWS CLI config to take accounts from. Required.
		ConfigFile string
		// Role is the profile name suffix of the read-only role: profiles named
		// "<anything>@<Role>" are audited. Required. An audit that needs write
		// credentials is a bug, so nothing else is read.
		Role string
		// ExtraRegion is a second region to sweep per account, or empty.
		ExtraRegion string
		// Declared reports whether a parameter name is explained. Required.
		Declared func(name string) bool
		// List reads the names. Required; [SSMLister] is the real one.
		List Lister
	}

	// DescribeParametersAPI is the part of the SSM client ListParameters uses.
	DescribeParametersAPI = ssm.DescribeParametersAPIClient
)

// ReadAccounts groups the config's read-only profiles by ACCOUNT, and visits
// each account's regions with every profile that names it.
//
// Keyed on the account id, not the profile name: two profiles can name ONE
// account (in other regions, or under a second name), and an audit that counts
// a profile as an account reports the same parameter twice and makes the
// estate look twice as dirty as it is. A profile without sso_account_id or
// region is skipped.
func ReadAccounts(configFile, role, extraRegion string) ([]Account, error) {
	if role == "" {
		return nil, errors.New("ssmaudit: Role is required")
	}

	cfgFile, err := ini.Load(configFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configFile, err)
	}

	profiles := map[string][]string{}
	regions := map[string]map[string]bool{}

	for _, sec := range cfgFile.Sections() {
		name := strings.TrimPrefix(sec.Name(), "profile ")
		if !strings.HasSuffix(name, "@"+role) {
			continue
		}

		id := sec.Key("sso_account_id").String()
		region := sec.Key("region").String()

		if id == "" || region == "" {
			continue
		}

		profiles[id] = append(profiles[id], name)

		if regions[id] == nil {
			regions[id] = map[string]bool{}
		}

		regions[id][region] = true

		if extraRegion != "" {
			regions[id][extraRegion] = true
		}
	}

	var out []Account

	for id, rs := range regions {
		for region := range rs {
			// EVERY profile of the account, in every one of its regions: a
			// profile's own `region` says where it usually points, not which
			// regions its role can read. Attaching profiles per region instead
			// leaves an account reachable in one region and "forbidden" in
			// another for no reason but which SSO role happened to be written
			// with that region.
			out = append(out, Account{Profiles: profiles[id], ID: id, Region: region})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}

		return out[i].Region < out[j].Region
	})

	return out, nil
}

// Audit lists the parameters of every account the config names and judges each
// name with Declared. It returns an error only when the config cannot be read
// or names no read-only profile; undeclared parameters and unreachable
// accounts are in the Result.
func Audit(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Declared == nil || cfg.List == nil {
		return nil, errors.New("ssmaudit: Declared and List are required")
	}

	accounts, err := ReadAccounts(cfg.ConfigFile, cfg.Role, cfg.ExtraRegion)
	if err != nil {
		return nil, err
	}

	if len(accounts) == 0 {
		return nil, errors.New("no " + cfg.Role + " profiles in " + cfg.ConfigFile)
	}

	res := &Result{}

	for _, acct := range accounts {
		profile, names, err := listFirst(ctx, cfg.List, acct)
		if err != nil {
			// A profile the operator cannot assume is reported, not fatal: an
			// audit that stops at the first closed door never reaches the
			// accounts it can see.
			res.Skipped = append(res.Skipped, Skipped{Account: acct, Err: err})

			continue
		}

		for _, name := range names {
			if cfg.Declared(name) {
				res.Declared++

				continue
			}

			res.Undeclared = append(res.Undeclared, Finding{
				Account: fmt.Sprintf("%s %s via %s", acct.ID, acct.Region, profile),
				Name:    name,
			})
		}
	}

	return res, nil
}

// listFirst tries the account's profiles in order and returns the first
// successful listing, or the last error when none works.
func listFirst(ctx context.Context, list Lister, acct Account) (profile string, names []string, err error) {
	lastErr := errors.New("no profile")

	for _, candidate := range acct.Profiles {
		found, listErr := list(ctx, candidate, acct.Region)
		if listErr == nil {
			return candidate, found, nil
		}

		lastErr = listErr
	}

	return "", nil, lastErr
}

// SSMLister is the Lister over the real SSM client. Each call loads the
// profile from configFile alone (not the operator's own ~/.aws/config) and
// pages DescribeParameters.
func SSMLister(configFile string) Lister {
	return func(ctx context.Context, profile, region string) ([]string, error) {
		awsCfg, err := config.LoadDefaultConfig(ctx,
			config.WithSharedConfigFiles([]string{configFile}),
			config.WithSharedConfigProfile(profile),
			config.WithRegion(region))
		if err != nil {
			return nil, err
		}

		return ListParameters(ctx, ssm.NewFromConfig(awsCfg))
	}
}

// ListParameters returns every parameter name the client sees, sorted.
func ListParameters(ctx context.Context, api DescribeParametersAPI) ([]string, error) {
	var names []string

	pages := ssm.NewDescribeParametersPaginator(api, &ssm.DescribeParametersInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for i := range page.Parameters {
			if p := page.Parameters[i].Name; p != nil {
				names = append(names, *p)
			}
		}
	}

	sort.Strings(names)

	return names, nil
}

// Write prints the result: the declared count, the accounts nobody could
// reach, and the undeclared names grouped by account. hint, when not empty, is
// printed after a non-empty undeclared list: what the caller wants done about
// one.
func (r *Result) Write(w io.Writer, hint string) error {
	var err error

	p := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(w, format, a...)
		}
	}

	p("declared parameters: %d\n", r.Declared)

	if len(r.Skipped) > 0 {
		p("\nnot reachable with this operator's grants (%d):\n", len(r.Skipped))

		for _, s := range r.Skipped {
			p("  - %s %s (tried %s): %v\n", s.Account.ID, s.Account.Region, strings.Join(s.Account.Profiles, ", "), s.Err)
		}
	}

	if len(r.Undeclared) == 0 {
		p("\nno undeclared parameters: SSM holds only what is written down.\n")

		return err
	}

	p("\nUNDECLARED (%d) -- each is either residue nobody wrote down, or debris:\n", len(r.Undeclared))

	byAccount := map[string][]string{}
	for _, f := range r.Undeclared {
		byAccount[f.Account] = append(byAccount[f.Account], f.Name)
	}

	accounts := make([]string, 0, len(byAccount))
	for a := range byAccount {
		accounts = append(accounts, a)
	}

	sort.Strings(accounts)

	for _, a := range accounts {
		p("\n  %s (%d)\n", a, len(byAccount[a]))

		for _, n := range byAccount[a] {
			p("    %s\n", n)
		}
	}

	if hint != "" {
		p("\n%s\n", hint)
	}

	return err
}
