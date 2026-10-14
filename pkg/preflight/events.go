package preflight

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/events"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optpreview"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"

	"github.com/truvity/aws-structure/pkg/registry"
)

// StepsFromEvents keeps the resource steps of a preview's engine events.
func StepsFromEvents(evs []apitype.EngineEvent) []Step {
	var out []Step

	for i := range evs {
		pre := evs[i].ResourcePreEvent
		if pre == nil {
			continue
		}

		m := pre.Metadata
		s := Step{Op: string(m.Op), URN: m.URN, Type: m.Type}

		if m.Old != nil {
			s.Old = m.Old.Inputs
		}

		if m.New != nil {
			s.New = m.New.Inputs
		}

		out = append(out, s)
	}

	return out
}

// ReadEventLog reads the file `pulumi preview --event-log <file>` writes: one
// JSON engine event per line.
func ReadEventLog(r io.Reader) ([]apitype.EngineEvent, error) {
	var out []apitype.EngineEvent

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)

	for line := 1; sc.Scan(); line++ {
		if len(sc.Bytes()) == 0 {
			continue
		}

		var ev apitype.EngineEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return nil, fmt.Errorf("event log line %d: %w", line, err)
		}

		out = append(out, ev)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read event log: %w", err)
	}

	return out, nil
}

// Opts configures Check and Run.
type Opts struct {
	// Registry is the loaded, validated registry. Required.
	Registry *registry.Registry
	// BreakGlass identifies the break-glass assignments in the plan by id;
	// nil skips the plan half of that guard (the registry half still runs).
	BreakGlass *BreakGlassAssignment
	// Now decides which waivers have expired. Zero means time.Now().
	Now time.Time
}

// Check runs both guards: Lockout on the registry and Plan on the steps, with
// the protected targets and waivers the registry declares.
func Check(steps []Step, o Opts) []Finding {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}

	out := Lockout(o.Registry, now)

	return append(out, Plan(steps, PlanOpts{
		BreakGlass:       o.BreakGlass,
		ProtectedTargets: ProtectedTargets(o.Registry),
		Waived:           Waived(o.Registry, now),
	})...)
}

// Run previews the stack (read-only), collects its steps and returns Check's
// findings. A failed preview is an error, not a finding.
func Run(ctx context.Context, stack auto.Stack, o Opts) ([]Finding, error) {
	type collected struct {
		evs []apitype.EngineEvent
		err error
	}

	ch := make(chan events.EngineEvent)
	done := make(chan collected, 1)

	go func() {
		var c collected
		for ev := range ch {
			if ev.Error != nil && c.err == nil {
				c.err = ev.Error
			}
			c.evs = append(c.evs, ev.EngineEvent)
		}
		done <- c
	}()

	if _, err := stack.Preview(ctx, optpreview.EventStreams(ch)); err != nil {
		// The stream may never have started; do not wait for it.
		return nil, fmt.Errorf("preview %s: %w", stack.Name(), err)
	}

	c := <-done
	if c.err != nil {
		// A lost event could be the replace this guard exists for.
		return nil, fmt.Errorf("preview %s: event stream: %w", stack.Name(), c.err)
	}

	return Check(StepsFromEvents(c.evs), o), nil
}
