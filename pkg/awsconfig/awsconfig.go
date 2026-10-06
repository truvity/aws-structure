// Package awsconfig renders the AWS CLI config file of a set of Identity
// Center accounts: one sso-session, a [default] profile that mirrors one of the
// profiles, and a profile for every (account, role) pair, in the order the
// caller gives.
//
// Mechanism only. Which accounts exist, which roles each one carries, what the
// session is called and which profile is the daily driver are inputs; nothing
// here names an organization. The output is deterministic, so a checked-in copy
// can be compared with a fresh render.
package awsconfig

import (
	"errors"
	"fmt"
	"strings"
)

type (
	// Session is the Identity Center session every profile signs in through.
	Session struct {
		// Name is the section's name and each profile's sso_session. Required.
		Name string
		// StartURL is the access portal URL. Required.
		StartURL string
		// Region is the Identity Center instance's region. Required.
		Region string
		// RegistrationScopes is sso_registration_scopes. Required.
		RegistrationScopes string
	}

	// Role is one role an account carries.
	Role struct {
		// Name is the profile name's suffix: "<account profile>@<Name>".
		Name string
		// SSORole is the permission set's name in Identity Center
		// (sso_role_name).
		SSORole string
	}

	// Account is one AWS account and the roles its profiles are made for. The
	// caller decides which roles an account has; an account whose permission
	// sets were never renamed carries the ones it HAS, because a profile for a
	// role that does not exist reads as "no access" instead of "no such role".
	Account struct {
		// Profile is the profile name's prefix. Required.
		Profile   string
		AccountID string
		Region    string
		Roles     []Role
	}

	// Profile is one rendered profile section.
	Profile struct {
		Name      string
		AccountID string
		RoleName  string
		Region    string
	}

	// Section is a run of profiles under one comment.
	Section struct {
		// Comment is written above the section's first profile, verbatim
		// ("# ..."). Empty writes none.
		Comment  string
		Profiles []Profile
	}

	// Config is a whole file.
	Config struct {
		// Header is written at the top of the file, verbatim ("# ...").
		Header  string
		Session Session
		// Default names the profile [default] mirrors. It must be one of the
		// sections' profiles.
		Default  string
		Sections []Section
	}
)

// Profiles expands the account into one profile per role, in role order.
func (a Account) Profiles() []Profile {
	out := make([]Profile, 0, len(a.Roles))

	for _, r := range a.Roles {
		out = append(out, Profile{Name: a.Profile + "@" + r.Name, AccountID: a.AccountID, RoleName: r.SSORole, Region: a.Region})
	}

	return out
}

// Render writes the config file. It refuses a missing session field, a profile
// name that appears twice and a Default that no section holds.
func Render(c Config) (string, error) {
	var errs []error

	for name, v := range map[string]string{
		"Session.Name": c.Session.Name, "Session.StartURL": c.Session.StartURL,
		"Session.Region": c.Session.Region, "Session.RegistrationScopes": c.Session.RegistrationScopes,
		"Default": c.Default,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("awsconfig: %s is empty", name))
		}
	}

	if len(errs) > 0 {
		return "", errors.Join(errs...)
	}

	var def *Profile

	seen := map[string]struct{}{}

	for i := range c.Sections {
		for j := range c.Sections[i].Profiles {
			p := &c.Sections[i].Profiles[j]

			if _, dup := seen[p.Name]; dup {
				return "", fmt.Errorf("duplicate profile name: %q", p.Name)
			}

			seen[p.Name] = struct{}{}

			if p.Name == c.Default {
				def = p
			}
		}
	}

	if def == nil {
		return "", fmt.Errorf("default profile %q not found among the profiles", c.Default)
	}

	var blocks []string

	if c.Header != "" {
		blocks = append(blocks, c.Header+"\n"+session(c.Session))
	} else {
		blocks = append(blocks, session(c.Session))
	}

	blocks = append(blocks, fmt.Sprintf("# Daily driver — mirrors %s (bare tools act on the working account)\n[default]\n%s", def.Name, keys(c.Session.Name, def)))

	for _, s := range c.Sections {
		for i := range s.Profiles {
			p := &s.Profiles[i]

			comment := ""
			if i == 0 && s.Comment != "" {
				comment = s.Comment + "\n"
			}

			blocks = append(blocks, fmt.Sprintf("%s[profile %s]\n%s", comment, p.Name, keys(c.Session.Name, p)))
		}
	}

	return strings.Join(blocks, "\n"), nil
}

func session(s Session) string {
	return fmt.Sprintf("[sso-session %s]\nsso_start_url = %s\nsso_region = %s\nsso_registration_scopes = %s\n",
		s.Name, s.StartURL, s.Region, s.RegistrationScopes)
}

func keys(sessionName string, p *Profile) string {
	return fmt.Sprintf("sso_session = %s\nsso_account_id = %s\nsso_role_name = %s\nregion = %s\n", sessionName, p.AccountID, p.RoleName, p.Region)
}
