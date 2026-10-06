package cost

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	accountIDPattern = regexp.MustCompile(`^\d{12}$`)
	namePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// categoryValuePattern is what Cost Explorer accepts as a literal cost
	// category value: letters, digits, spaces, `-` and `_`, no leading or
	// trailing space. AWS's own regexp reads `/` as inside its range yet
	// rejects it (a `nodes/ci` value failed at apply), so it is spelled out
	// strictly here.
	categoryValuePattern = regexp.MustCompile(`^[\p{L}\p{N}]([\p{L}\p{N} _-]*[\p{L}\p{N}_-])?$`)
	serviceCodePattern   = regexp.MustCompile(`^[A-Za-z0-9]+$`)
	monitorARNPattern    = regexp.MustCompile(`^arn:[a-z-]+:ce::\d{12}:anomalymonitor/[0-9a-f-]{36}$`)
)

// NodePoolValue is the category value of a node pool's spend.
func NodePoolValue(pool string) string { return "nodes-" + pool }

// Validate reports every problem with the spec at once, or returns nil. It
// checks the shapes AWS refuses only at apply, where a preview never sees
// them: account ids and names, the monitor ARN of the given partition, a
// category's value pattern, service codes and node pool names.
func (s *Spec) Validate(partition string) error {
	var errs []error

	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf("spec: "+format, args...)) }

	if s.TotalMonthlyUSD <= 0 {
		bad("TotalMonthlyUSD must be positive")
	}

	if len(s.Accounts) == 0 {
		bad("Accounts is empty")
	}

	names := map[string]bool{}
	ids := map[string]bool{}

	for i, a := range s.Accounts {
		if !namePattern.MatchString(a.Name) {
			bad("Accounts[%d].Name %q must match %s", i, a.Name, namePattern)
		}

		if !accountIDPattern.MatchString(a.ID) {
			bad("Accounts[%d].ID %q is not a 12-digit account id", i, a.ID)
		}

		if a.MonthlyUSD <= 0 {
			bad("Accounts[%d].MonthlyUSD must be positive", i)
		}

		if names[a.Name] || ids[a.ID] {
			bad("Accounts[%d]: name %q or id %q repeats", i, a.Name, a.ID)
		}

		names[a.Name], ids[a.ID] = true, true
	}

	if s.AnomalyThresholdUSD <= 0 {
		bad("AnomalyThresholdUSD must be positive")
	}

	if s.DefaultMonitor.Name == "" {
		bad("DefaultMonitor.Name is required")
	}

	if !monitorARNPattern.MatchString(s.DefaultMonitor.ARN) || !hasPartition(s.DefaultMonitor.ARN, partition) {
		bad("DefaultMonitor.ARN %q is not a Cost Anomaly monitor ARN of partition %q", s.DefaultMonitor.ARN, partition)
	}

	if s.Category != nil {
		errs = append(errs, s.Category.validate(names)...)
	}

	return errors.Join(errs...)
}

func hasPartition(arn, partition string) bool {
	prefix := "arn:" + partition + ":"

	return len(arn) >= len(prefix) && arn[:len(prefix)] == prefix
}

func (c *Category) validate(accountNames map[string]bool) []error {
	var errs []error

	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf("spec: Category."+format, args...)) }

	if c.Name == "" {
		bad("Name is required")
	}

	if c.OtherValue == "" || c.DefaultValue == "" {
		bad("OtherValue and DefaultValue are required")
	}

	if c.OtherValue == c.DefaultValue {
		bad("OtherValue and DefaultValue must differ (one is outside the account, the other inside it)")
	}

	if !accountNames[c.Account] {
		bad("Account %q is not in Accounts", c.Account)
	}

	seen := map[string]bool{}

	for _, p := range c.NodePools {
		if !namePattern.MatchString(p.Pool) || seen[p.Pool] {
			bad("NodePools: %q is not a unique node pool name", p.Pool)
		}

		seen[p.Pool] = true
	}

	svc := map[string]bool{}

	for i, s := range c.Services {
		if s.Service == "" || s.Value == "" || svc[s.Service] {
			bad("Services[%d]: Service and Value are required and a service appears once", i)
		}

		if !serviceCodePattern.MatchString(s.Service) {
			bad("Services[%d]: %q is not a service code (AmazonEC2, AWSELB: no spaces; a display name is refused by AWS)", i, s.Service)
		}

		svc[s.Service] = true
	}

	// Every literal value reaches the API as is; one that breaks AWS's
	// pattern fails the whole category at apply.
	values := []string{"tax", c.OtherValue, c.DefaultValue}
	for _, p := range c.NodePools {
		values = append(values, p.Value)
	}

	for _, s := range c.Services {
		values = append(values, s.Value)
	}

	for _, v := range values {
		if !categoryValuePattern.MatchString(v) {
			bad("value %q does not match AWS's pattern %s", v, categoryValuePattern)
		}
	}

	return errs
}
