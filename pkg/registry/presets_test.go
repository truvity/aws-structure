package registry_test

import (
	"testing"

	"github.com/truvity/aws-structure/pkg/registry"
)

// The preset is a compliance contract: a change to any field is a change to
// every account that uses it, so the values are pinned here.
func TestISO27001PasswordPolicy(t *testing.T) {
	want := registry.PasswordPolicy{
		MinimumLength:    14,
		MaxAgeDays:       90,
		ReusePrevention:  24,
		RequireSymbols:   true,
		RequireNumbers:   true,
		RequireUppercase: true,
		RequireLowercase: true,
	}

	got := registry.ISO27001PasswordPolicy()
	if got != want {
		t.Fatalf("ISO27001PasswordPolicy() = %+v, want %+v", got, want)
	}

	got.MinimumLength = 8
	if registry.ISO27001PasswordPolicy().MinimumLength != 14 {
		t.Fatal("a caller's copy changed the preset")
	}
}
