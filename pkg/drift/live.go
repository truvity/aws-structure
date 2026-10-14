package drift

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

// OrganizationsAPI is the part of the AWS Organizations client Read uses.
type OrganizationsAPI interface {
	organizations.ListRootsAPIClient
	organizations.ListOrganizationalUnitsForParentAPIClient
	organizations.ListAccountsForParentAPIClient
	organizations.ListPoliciesForTargetAPIClient
}

// SSOAdminAPI is the part of the Identity Center admin client Read uses.
type SSOAdminAPI interface {
	ssoadmin.ListPermissionSetsAPIClient
	ssoadmin.ListAccountAssignmentsAPIClient
	DescribePermissionSet(ctx context.Context, in *ssoadmin.DescribePermissionSetInput,
		opts ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
}

// IdentityStoreAPI is the part of the identity store client Read uses.
type IdentityStoreAPI interface {
	identitystore.ListGroupsAPIClient
	identitystore.ListUsersAPIClient
}

// Clients are the AWS clients of the management account (Organizations) and
// of the Identity Center instance's region (admin and identity store).
type Clients struct {
	Organizations OrganizationsAPI
	SSOAdmin      SSOAdminAPI
	IdentityStore IdentityStoreAPI
	// InstanceARN and IdentityStoreID identify the Identity Center instance.
	InstanceARN     string
	IdentityStoreID string
}

// Live is what Read found.
type Live struct {
	RootID   string
	OUs      []LiveOU
	Accounts []LiveAccount
	// Policies are the service control policy names attached to each target
	// (the root, an OU or an account), by target id.
	Policies map[string][]string

	// PermissionSets are by ARN; Groups and Users are names by id.
	PermissionSets map[string]string
	Groups         map[string]string
	Users          map[string]string
	Assignments    []LiveAssignment
}

// LiveOU is an organizational unit.
type LiveOU struct {
	ID, Name, ParentID string
}

// LiveAccount is a member account.
type LiveAccount struct {
	ID, Name, Email, ParentID, State string
}

// LiveAssignment is one account assignment, by id.
type LiveAssignment struct {
	AccountID, PermissionSetARN, PrincipalType, PrincipalID string
}

// Read walks the organization and the Identity Center instance. Closed and
// suspended accounts are kept (with their State) so Compare can tell a
// declared account that was closed from one that never existed.
func Read(ctx context.Context, c Clients) (*Live, error) {
	if c.Organizations == nil || c.SSOAdmin == nil || c.IdentityStore == nil ||
		c.InstanceARN == "" || c.IdentityStoreID == "" {
		return nil, errors.New("drift: Clients needs all three clients, InstanceARN and IdentityStoreID")
	}

	l := &Live{Policies: map[string][]string{}}

	if err := l.readOrganization(ctx, c.Organizations); err != nil {
		return nil, fmt.Errorf("drift: read organization: %w", err)
	}

	if err := l.readIdentityCenter(ctx, c); err != nil {
		return nil, fmt.Errorf("drift: read Identity Center: %w", err)
	}

	return l, nil
}

func (l *Live) readOrganization(ctx context.Context, api OrganizationsAPI) error {
	roots, err := organizations.NewListRootsPaginator(api, &organizations.ListRootsInput{}).NextPage(ctx)
	if err != nil {
		return fmt.Errorf("list roots: %w", err)
	}

	if len(roots.Roots) != 1 {
		return fmt.Errorf("found %d roots, want 1", len(roots.Roots))
	}

	l.RootID = aws.ToString(roots.Roots[0].Id)

	parents := []string{l.RootID}
	for len(parents) > 0 {
		parent := parents[0]
		parents = parents[1:]

		if err := l.readTarget(ctx, api, parent); err != nil {
			return err
		}

		ous := organizations.NewListOrganizationalUnitsForParentPaginator(api,
			&organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(parent)})
		for ous.HasMorePages() {
			page, err := ous.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("list OUs of %s: %w", parent, err)
			}

			for _, o := range page.OrganizationalUnits {
				id := aws.ToString(o.Id)
				l.OUs = append(l.OUs, LiveOU{ID: id, Name: aws.ToString(o.Name), ParentID: parent})
				parents = append(parents, id)
			}
		}

		accts := organizations.NewListAccountsForParentPaginator(api,
			&organizations.ListAccountsForParentInput{ParentId: aws.String(parent)})
		for accts.HasMorePages() {
			page, err := accts.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("list accounts of %s: %w", parent, err)
			}

			for i := range page.Accounts {
				a := &page.Accounts[i]
				id := aws.ToString(a.Id)
				l.Accounts = append(l.Accounts, LiveAccount{
					ID: id, Name: aws.ToString(a.Name), Email: aws.ToString(a.Email), ParentID: parent, State: string(a.State),
				})

				if err := l.readTarget(ctx, api, id); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (l *Live) readTarget(ctx context.Context, api OrganizationsAPI, target string) error {
	p := organizations.NewListPoliciesForTargetPaginator(api, &organizations.ListPoliciesForTargetInput{
		TargetId: aws.String(target), Filter: orgtypes.PolicyTypeServiceControlPolicy,
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list policies of %s: %w", target, err)
		}

		for _, s := range page.Policies {
			l.Policies[target] = append(l.Policies[target], aws.ToString(s.Name))
		}
	}

	sort.Strings(l.Policies[target])

	return nil
}

func (l *Live) readIdentityCenter(ctx context.Context, c Clients) error {
	l.PermissionSets, l.Groups, l.Users = map[string]string{}, map[string]string{}, map[string]string{}

	sets := ssoadmin.NewListPermissionSetsPaginator(c.SSOAdmin, &ssoadmin.ListPermissionSetsInput{InstanceArn: aws.String(c.InstanceARN)})
	for sets.HasMorePages() {
		page, err := sets.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list permission sets: %w", err)
		}

		for _, arn := range page.PermissionSets {
			d, err := c.SSOAdmin.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
				InstanceArn: aws.String(c.InstanceARN), PermissionSetArn: aws.String(arn),
			})
			if err != nil {
				return fmt.Errorf("describe permission set %s: %w", arn, err)
			}

			if d.PermissionSet == nil {
				return fmt.Errorf("describe permission set %s: empty answer", arn)
			}

			l.PermissionSets[arn] = aws.ToString(d.PermissionSet.Name)
		}
	}

	groups := identitystore.NewListGroupsPaginator(c.IdentityStore, &identitystore.ListGroupsInput{IdentityStoreId: aws.String(c.IdentityStoreID)})
	for groups.HasMorePages() {
		page, err := groups.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list groups: %w", err)
		}

		for _, g := range page.Groups {
			l.Groups[aws.ToString(g.GroupId)] = aws.ToString(g.DisplayName)
		}
	}

	users := identitystore.NewListUsersPaginator(c.IdentityStore, &identitystore.ListUsersInput{IdentityStoreId: aws.String(c.IdentityStoreID)})
	for users.HasMorePages() {
		page, err := users.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}

		for i := range page.Users {
			l.Users[aws.ToString(page.Users[i].UserId)] = aws.ToString(page.Users[i].UserName)
		}
	}

	arns := make([]string, 0, len(l.PermissionSets))
	for arn := range l.PermissionSets {
		arns = append(arns, arn)
	}

	sort.Strings(arns)

	for _, acct := range l.Accounts {
		if acct.State != "" && acct.State != string(orgtypes.AccountStateActive) {
			continue
		}

		for _, arn := range arns {
			p := ssoadmin.NewListAccountAssignmentsPaginator(c.SSOAdmin, &ssoadmin.ListAccountAssignmentsInput{
				InstanceArn: aws.String(c.InstanceARN), AccountId: aws.String(acct.ID), PermissionSetArn: aws.String(arn),
			})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("list assignments of %s on %s: %w", arn, acct.ID, err)
				}

				for _, a := range page.AccountAssignments {
					l.Assignments = append(l.Assignments, LiveAssignment{
						AccountID: aws.ToString(a.AccountId), PermissionSetARN: aws.ToString(a.PermissionSetArn),
						PrincipalType: string(a.PrincipalType), PrincipalID: aws.ToString(a.PrincipalId),
					})
				}
			}
		}
	}

	return nil
}
