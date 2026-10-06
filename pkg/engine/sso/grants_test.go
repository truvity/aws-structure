package sso_test

import (
	"reflect"
	"testing"

	"github.com/truvity/aws-structure/pkg/engine/sso"
)

func TestGrantsFor(t *testing.T) {
	setOf := map[string]string{"top": "set-admin", "low": "set-viewer"}

	got := sso.GrantsFor("env", setOf, []sso.Holder{
		{Role: "ops", Level: "top", Groups: []string{"b@x", "a@x"}},
		{Role: "eng", Level: "low", Groups: []string{"c@x", "placeholder"}},
		{Role: "none", Level: "unknown", Groups: []string{"z@x"}},
	}, func(g string) bool { return g == "placeholder" })

	want := []sso.Grant{
		{Scope: "env", Set: "set-viewer", Group: "c@x", Role: "eng"},
		{Scope: "env", Set: "set-admin", Group: "a@x", Role: "ops"},
		{Scope: "env", Set: "set-admin", Group: "b@x", Role: "ops"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}

	if sso.GrantsFor("env", setOf, nil, nil) != nil {
		t.Error("no holders must give no grants")
	}
}
