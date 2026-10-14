package backend_test

import (
	"testing"

	"github.com/truvity/aws-structure/pkg/backend"
)

func TestSecretsProviderURL(t *testing.T) {
	const base = "awskms://alias/pulumi-state?awssdk=v2&region=region-a&profile=prof"

	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"plain", backend.SecretsProviderURL("region-a", "prof"), base},
		{"empty purpose", backend.SecretsProviderURL("region-a", "prof", backend.WithContextPurpose("")), base},
		{"purpose", backend.SecretsProviderURL("region-a", "prof", backend.WithContextPurpose("pulumi-state")),
			base + "&context_purpose=pulumi-state"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestURL(t *testing.T) {
	const want = "s3://pulumi-state-111122223333-region-a?awssdk=v2&region=region-a&profile=prof"

	if got := backend.URL("111122223333", "region-a", "prof"); got != want {
		t.Errorf("URL: %q, want %q", got, want)
	}
}
