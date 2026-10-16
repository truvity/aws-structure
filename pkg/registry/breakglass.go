package registry

// BreakGlassTargets are the accounts the break-glass assignment must reach by
// construction: every account that is not closed and has an id, wherever it
// sits (including directly under the organization root). An account without an
// id does not exist yet, so there is nothing to assign on; a closed account
// grants no assignment. pkg/engine/sso.DeployBreakGlass assigns exactly these.
func (r *Registry) BreakGlassTargets() []Account {
	var out []Account

	for _, a := range r.Accounts {
		if a.Closed || a.ID == "" {
			continue
		}

		out = append(out, a)
	}

	return out
}
