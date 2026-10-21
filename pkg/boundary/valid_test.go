package boundary_test

import (
	"encoding/json"
	"testing"

	"github.com/truvity/aws-structure/policy"
)

// Every document the package renders is a valid policy document of the policy
// module (unique Sids, one of Action and NotAction, no empty entry) and
// writes back to the same bytes through it.
func TestEveryDocumentIsAValidPolicy(t *testing.T) {
	all := map[string]string{}

	for name, d := range variants(t) {
		all["current/"+name] = d
	}

	for _, s := range []struct {
		prefix string
		docs   map[string]string
	}{{"legacy/", docs(t, spec())}, {"grun/", docs(t, grunSpec())}, {"both/", docs(t, bothSpec())}} {
		for name, d := range s.docs {
			all[s.prefix+name] = d
		}
	}

	if len(all) < 30 {
		t.Fatalf("only %d documents were checked", len(all))
	}

	for name, raw := range all {
		var d policy.Document
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}

		back, err := json.Marshal(d)
		if err != nil || string(back) != raw {
			t.Errorf("%s: written back differently (err %v)", name, err)
		}
	}
}
