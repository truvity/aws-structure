package awsconfig_test

import (
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/awsconfig"
)

func config() awsconfig.Config {
	acct := strings.Repeat("1", 12)
	a := awsconfig.Account{Profile: "dev", AccountID: acct, Region: "region-a", Roles: []awsconfig.Role{
		{Name: "admin", SSORole: "role-admin"}, {Name: "viewer", SSORole: "role-viewer"},
	}}
	old := awsconfig.Account{Profile: "old", AccountID: strings.Repeat("2", 12), Region: "region-b", Roles: []awsconfig.Role{{Name: "admin", SSORole: "admin"}}}

	return awsconfig.Config{
		Header:  "# GENERATED\n# Do not edit",
		Session: awsconfig.Session{Name: "org", StartURL: "https://example.test/start", Region: "region-b", RegistrationScopes: "sso:account:access"},
		Default: "dev@admin",
		Sections: []awsconfig.Section{
			{Comment: "# --- Old ---", Profiles: old.Profiles()},
			{Comment: "# --- New ---", Profiles: a.Profiles()},
		},
	}
}

func TestRender(t *testing.T) {
	got, err := awsconfig.Render(config())
	if err != nil {
		t.Fatal(err)
	}

	acct, oldAcct := strings.Repeat("1", 12), strings.Repeat("2", 12)
	want := `# GENERATED
# Do not edit
[sso-session org]
sso_start_url = https://example.test/start
sso_region = region-b
sso_registration_scopes = sso:account:access

# Daily driver — mirrors dev@admin (bare tools act on the working account)
[default]
sso_session = org
sso_account_id = ` + acct + `
sso_role_name = role-admin
region = region-a

# --- Old ---
[profile old@admin]
sso_session = org
sso_account_id = ` + oldAcct + `
sso_role_name = admin
region = region-b

# --- New ---
[profile dev@admin]
sso_session = org
sso_account_id = ` + acct + `
sso_role_name = role-admin
region = region-a

[profile dev@viewer]
sso_session = org
sso_account_id = ` + acct + `
sso_role_name = role-viewer
region = region-a
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderUsesTheSessionNameOfTheConfig(t *testing.T) {
	c := config()
	c.Session.Name = "other"

	got, err := awsconfig.Render(c)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(got, "sso_session = org") || strings.Count(got, "sso_session = other") != 4 {
		t.Errorf("every profile must sign in through the configured session:\n%s", got)
	}
}

func TestRenderRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*awsconfig.Config)
		want   string
	}{
		"missing default": {func(c *awsconfig.Config) { c.Default = "nope@admin" }, "not found"},
		"empty default":   {func(c *awsconfig.Config) { c.Default = "" }, "Default is empty"},
		"empty session":   {func(c *awsconfig.Config) { c.Session.StartURL = "" }, "Session.StartURL is empty"},
		"duplicate profile": {func(c *awsconfig.Config) {
			c.Sections[0].Profiles = append(c.Sections[0].Profiles, c.Sections[1].Profiles[0])
		}, "duplicate profile name"},
	} {
		c := config()
		tc.mutate(&c)

		if _, err := awsconfig.Render(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
}
