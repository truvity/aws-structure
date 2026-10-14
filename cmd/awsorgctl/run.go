package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/truvity/aws-structure/pkg/awsconfig"
	"github.com/truvity/aws-structure/pkg/preflight"
	"github.com/truvity/aws-structure/pkg/registry"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

const usage = `usage: awsorgctl <command> [flags]

commands:
  validate      load and validate a registry
  preflight     judge a preview's event log (pulumi preview --event-log) and the registry
  drift         compare the live organization and Identity Center with the registry
  access-roles  write the Identity Center roles of every account as YAML
  aws-ini       render the AWS CLI config of the registry's accounts and assigned permission sets
  version       print the version

run "awsorgctl <command> -h" for its flags`

// errFindings marks a run that worked and found something to refuse.
var errFindings = errors.New("findings")

type command func(ctx context.Context, args []string, stdout io.Writer) error

func commands() map[string]command {
	return map[string]command{
		"validate":     cmdValidate,
		"preflight":    cmdPreflight,
		"drift":        cmdDrift,
		"access-roles": cmdAccessRoles,
		"aws-ini":      cmdAWSIni,
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		_, _ = fmt.Fprintln(stdout, "awsorgctl "+Version)

		return exitOK
	}

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = fmt.Fprintln(stderr, usage)

		return exitUsage
	}

	cmd, ok := commands()[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "awsorgctl: unknown command %q\n\n%s\n", args[0], usage)

		return exitUsage
	}

	err := cmd(context.Background(), args[1:], stdout)

	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errFindings):
		return exitFindings
	case errors.Is(err, flag.ErrHelp):
		return exitUsage
	default:
		_, _ = fmt.Fprintf(stderr, "awsorgctl %s: %v\n", args[0], err)

		return exitUsage
	}
}

// flags is a flag set that reports to stdout's caller through errors only.
func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("awsorgctl "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	return fs
}

func loadRegistry(path string) (*registry.Registry, error) {
	if path == "" {
		return nil, errors.New("-registry is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return registry.Parse(data)
}

func cmdValidate(_ context.Context, args []string, stdout io.Writer) error {
	fs := flags("validate")
	path := fs.String("registry", "", "registry file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := loadRegistry(*path)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(stdout, "ok: %d OUs, %d accounts, %d permission sets, %d assignments\n",
		len(reg.OUs), len(reg.Accounts), len(reg.IdentityCenter.PermissionSets), len(reg.IdentityCenter.Assignments))

	return err
}

func cmdPreflight(_ context.Context, args []string, stdout io.Writer) error {
	fs := flags("preflight")
	path := fs.String("registry", "", "registry file (required)")
	events := fs.String("events", "", "the file `pulumi preview --event-log <file>` wrote (required)")
	bgSet := fs.String("break-glass-set", "", "ARN of the break-glass permission set, to guard its assignments in the plan")
	bgPrincipal := fs.String("break-glass-principal", "", "id of the break-glass principal, to guard its assignments in the plan")
	today := fs.String("now", "", "the day waivers are judged on (YYYY-MM-DD); default today")

	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := loadRegistry(*path)
	if err != nil {
		return err
	}

	if *events == "" {
		return errors.New("-events is required")
	}

	f, err := os.Open(*events)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	evs, err := preflight.ReadEventLog(f)
	if err != nil {
		return err
	}

	o := preflight.Opts{Registry: reg}

	if *bgSet != "" || *bgPrincipal != "" {
		if *bgSet == "" || *bgPrincipal == "" {
			return errors.New("-break-glass-set and -break-glass-principal go together")
		}

		o.BreakGlass = &preflight.BreakGlassAssignment{PermissionSetARN: *bgSet, PrincipalID: *bgPrincipal}
	}

	if *today != "" {
		if o.Now, err = time.Parse(registry.DateLayout, *today); err != nil {
			return fmt.Errorf("-now: %w", err)
		}
	}

	steps := preflight.StepsFromEvents(evs)

	findings := preflight.Check(steps, o)
	if len(findings) == 0 {
		_, err = fmt.Fprintf(stdout, "preflight: clean (%d steps)\n", len(steps))

		return err
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].String() < findings[j].String() })

	for _, f := range findings {
		if _, err := fmt.Fprintln(stdout, "REFUSED "+f.String()); err != nil {
			return err
		}
	}

	return errFindings
}

func cmdAWSIni(_ context.Context, args []string, stdout io.Writer) error {
	fs := flags("aws-ini")
	path := fs.String("registry", "", "registry file (required)")
	startURL := fs.String("start-url", "", "Identity Center access portal URL (required)")
	ssoRegion := fs.String("sso-region", "", "Identity Center instance region (required)")
	region := fs.String("region", "", "region of every profile (required)")
	session := fs.String("session", "sso", "sso-session name")
	scopes := fs.String("scopes", "sso:account:access", "sso_registration_scopes")
	def := fs.String("default", "", "profile [default] mirrors (default: the first)")
	out := fs.String("out", "", "write to this file instead of stdout")

	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := loadRegistry(*path)
	if err != nil {
		return err
	}

	text, err := renderAWSIni(reg, awsconfig.Session{
		Name: *session, StartURL: *startURL, Region: *ssoRegion, RegistrationScopes: *scopes,
	}, *region, *def)
	if err != nil {
		return err
	}

	return write(*out, stdout, []byte(text))
}

// renderAWSIni renders one profile per account with an id and permission set
// assigned to it, named <account>@<set>.
func renderAWSIni(reg *registry.Registry, session awsconfig.Session, region, def string) (string, error) {
	var profiles []awsconfig.Profile

	sets := assignedSets(reg)

	for _, a := range reg.Accounts {
		if a.ID == "" {
			continue
		}

		acct := awsconfig.Account{Profile: a.Name, AccountID: a.ID, Region: region}
		for _, s := range sets[a.Name] {
			acct.Roles = append(acct.Roles, awsconfig.Role{Name: s, SSORole: s})
		}

		profiles = append(profiles, acct.Profiles()...)
	}

	if len(profiles) == 0 {
		return "", errors.New("no account with an id has an assigned permission set")
	}

	if def == "" {
		def = profiles[0].Name
	}

	return awsconfig.Render(awsconfig.Config{
		Header:   "# Generated by awsorgctl aws-ini from the registry; regenerate instead of editing.",
		Session:  session,
		Default:  def,
		Sections: []awsconfig.Section{{Profiles: profiles}},
	})
}

// assignedSets maps each account name to the permission sets any assignment
// grants on it, directly or through an OU at any depth, sorted.
func assignedSets(reg *registry.Registry) map[string][]string {
	parent := map[string]string{}
	for _, o := range reg.OUs {
		parent[o.Name] = o.Parent
	}

	under := map[string]map[string]bool{} // ou -> accounts

	for _, a := range reg.Accounts {
		seen := map[string]bool{}
		for ou := a.OU; ou != "" && !seen[ou]; ou = parent[ou] {
			seen[ou] = true

			if under[ou] == nil {
				under[ou] = map[string]bool{}
			}

			under[ou][a.Name] = true
		}
	}

	set := map[string]map[string]bool{}
	add := func(acct, ps string) {
		if set[acct] == nil {
			set[acct] = map[string]bool{}
		}

		set[acct][ps] = true
	}

	for _, as := range reg.IdentityCenter.Assignments {
		for _, a := range as.Accounts {
			add(a, as.PermissionSet)
		}

		for _, ou := range as.OUs {
			for a := range under[ou] {
				add(a, as.PermissionSet)
			}
		}
	}

	out := map[string][]string{}

	for acct, ps := range set {
		for p := range ps {
			out[acct] = append(out[acct], p)
		}

		sort.Strings(out[acct])
	}

	return out
}

func write(path string, stdout io.Writer, data []byte) error {
	if path == "" {
		_, err := stdout.Write(data)

		return err
	}

	return os.WriteFile(path, data, 0o600)
}
