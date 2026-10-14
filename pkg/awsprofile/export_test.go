package awsprofile

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// SetIdentity replaces the STS call GetAccountID makes.
func (m *Manager) SetIdentity(f func(ctx context.Context, cfg aws.Config) (string, error)) {
	m.identity = f
}
