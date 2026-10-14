package drift

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"go.yaml.in/yaml/v3"
)

// ssoRolePath is the IAM path of every role Identity Center provisions.
const ssoRolePath = "/aws-reserved/sso.amazonaws.com/"

// ssoRolePrefix starts the name of every such role:
// AWSReservedSSO_<permission set>_<suffix>.
const ssoRolePrefix = "AWSReservedSSO_"

// IAMAPI is the part of an account's IAM client AccessRoles uses.
type IAMAPI interface {
	iam.ListRolesAPIClient
}

// AccessRoleSet is the access-roles map: for every account, the role
// Identity Center provisioned for each permission set assigned there.
type AccessRoleSet struct {
	Accounts map[string]AccountRoles `yaml:"accounts"`
}

// AccountRoles are one account's roles, by permission set name.
type AccountRoles struct {
	AccountID string                `yaml:"account_id"`
	Roles     map[string]AccessRole `yaml:"roles"`
}

// AccessRole is one provisioned role.
type AccessRole struct {
	PermissionSet string `yaml:"permission_set"`
	RoleName      string `yaml:"role_name"`
	// RoleARN is the ARN with its /aws-reserved/sso.amazonaws.com/<region>/
	// path, as IAM returns it.
	RoleARN string `yaml:"role_arn"`
	// RoleARNPathless is the same role without the path, the form EKS
	// access entries and some trust policies need.
	RoleARNPathless string `yaml:"role_arn_pathless"`
}

// AccessRoles lists the Identity Center roles of every account (by name, to
// its id) through the IAM client clientFor returns for that account id. A
// role whose permission set cannot be told from its name is skipped.
func AccessRoles(ctx context.Context, accounts map[string]string,
	clientFor func(ctx context.Context, accountID string) (IAMAPI, error),
) (*AccessRoleSet, error) {
	out := &AccessRoleSet{Accounts: map[string]AccountRoles{}}

	names := make([]string, 0, len(accounts))
	for n := range accounts {
		names = append(names, n)
	}

	sort.Strings(names)

	for _, name := range names {
		id := accounts[name]

		client, err := clientFor(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("drift: IAM client for %s: %w", name, err)
		}

		roles := map[string]AccessRole{}

		p := iam.NewListRolesPaginator(client, &iam.ListRolesInput{PathPrefix: aws.String(ssoRolePath)})
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("drift: list roles of %s: %w", name, err)
			}

			for _, r := range page.Roles {
				roleName, arn := aws.ToString(r.RoleName), aws.ToString(r.Arn)

				set, ok := permissionSetOf(roleName)
				if !ok {
					continue
				}

				roles[set] = AccessRole{
					PermissionSet: set, RoleName: roleName, RoleARN: arn, RoleARNPathless: pathless(arn, roleName),
				}
			}
		}

		out.Accounts[name] = AccountRoles{AccountID: id, Roles: roles}
	}

	return out, nil
}

// permissionSetOf reads the permission set out of
// AWSReservedSSO_<set>_<suffix>; the set name may itself hold underscores.
func permissionSetOf(roleName string) (string, bool) {
	rest, ok := strings.CutPrefix(roleName, ssoRolePrefix)
	if !ok {
		return "", false
	}

	i := strings.LastIndex(rest, "_")
	if i <= 0 {
		return "", false
	}

	return rest[:i], true
}

// pathless drops the path from a role ARN: arn:<p>:iam::<id>:role/<path>/<name>
// becomes arn:<p>:iam::<id>:role/<name>.
func pathless(arn, roleName string) string {
	i := strings.Index(arn, ":role/")
	if i < 0 {
		return arn
	}

	return arn[:i] + ":role/" + roleName
}

// RenderAccessRoles writes the map as YAML under a generated-file header.
// Map keys are sorted, so a checked-in copy compares with a fresh render.
func RenderAccessRoles(set *AccessRoleSet, header string) ([]byte, error) {
	body, err := yaml.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("drift: render access roles: %w", err)
	}

	if header == "" {
		return body, nil
	}

	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
		b.WriteString("# " + line + "\n")
	}

	b.WriteString(string(body))

	return []byte(b.String()), nil
}
