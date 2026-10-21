package cdkbootstrap_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
	engine "github.com/truvity/aws-structure/pkg/engine/cdkbootstrap"
)

type registration struct {
	typ, name, parent, provider string
	dependencies                []string
	inputs                      resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []registration
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	reg := registration{typ: args.TypeToken, name: args.Name, inputs: args.Inputs}

	if rpc := args.RegisterRPC; rpc != nil {
		reg.parent = rpc.GetParent()
		reg.provider = rpc.GetProvider()
		reg.dependencies = rpc.GetDependencies()
	}

	r.mu.Lock()
	r.regs = append(r.regs, reg)
	r.mu.Unlock()

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

func bootstrap() cdkbootstrap.Bootstrap {
	return cdkbootstrap.Bootstrap{
		Qualifier:      "app",
		DeployBoundary: "pb@tech-deploy",
		Accounts:       []string{"dev"},
		Regions:        []string{"eu-west-1"},
	}
}

func run(t *testing.T, edit func(*engine.Args), dependsOn bool) ([]registration, error) {
	t.Helper()

	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("eu-west-1")})
		if err != nil {
			return err
		}

		args := &engine.Args{
			Account:   "dev",
			Region:    "eu-west-1",
			Partition: "aws",
			Bootstrap: bootstrap(),
			Provider:  p,
		}

		if dependsOn {
			policy, err := pulumiaws.NewProvider(ctx, "boundary-stand-in", &pulumiaws.ProviderArgs{Region: pulumi.String("eu-west-1")})
			if err != nil {
				return err
			}

			args.DependsOn = []pulumi.Resource{policy}
		}

		if edit != nil {
			edit(args)
		}

		_, err = engine.New(ctx, "cdkbootstrap-app-dev-eu-west-1", args)

		return err
	}, pulumi.WithMocks("proj", "stack", rec))

	return rec.regs, err
}

func find(regs []registration, typ string) []registration {
	var out []registration

	for _, r := range regs {
		if r.typ == typ {
			out = append(out, r)
		}
	}

	return out
}

func TestStack(t *testing.T) {
	regs, err := run(t, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	comps := find(regs, engine.TypeToken)
	if len(comps) != 1 || comps[0].name != "cdkbootstrap-app-dev-eu-west-1" {
		t.Fatalf("components = %+v", comps)
	}

	stacks := find(regs, "aws:cloudformation/stack:Stack")
	if len(stacks) != 1 {
		t.Fatalf("%d stacks", len(stacks))
	}

	s := stacks[0]
	if s.name != "cdkbootstrap-app-dev-eu-west-1-stack" {
		t.Errorf("stack logical name = %q", s.name)
	}

	if !strings.HasSuffix(s.parent, "::cdkbootstrap-app-dev-eu-west-1") {
		t.Errorf("parent = %q", s.parent)
	}

	if !strings.Contains(s.provider, "::p::") {
		t.Errorf("provider = %q", s.provider)
	}

	if len(s.dependencies) != 1 || !strings.Contains(s.dependencies[0], "boundary-stand-in") {
		t.Errorf("dependencies = %v", s.dependencies)
	}

	in := s.inputs.Mappable()

	if in["name"] != "CDKToolkit-app" {
		t.Errorf("name = %v", in["name"])
	}

	if caps, _ := in["capabilities"].([]any); len(caps) != 1 || caps[0] != "CAPABILITY_NAMED_IAM" {
		t.Errorf("capabilities = %v", in["capabilities"])
	}

	params, _ := in["parameters"].(map[string]any)
	if params["Qualifier"] != "app" || params["InputPermissionsBoundary"] != "pb@tech-deploy" ||
		params["CloudFormationExecutionPolicies"] != "arn:aws:iam::aws:policy/AdministratorAccess" || params["TrustedAccounts"] != "" {
		t.Errorf("parameters = %v", params)
	}

	body, _ := in["templateBody"].(string)

	want, err := cdkbootstrap.Render()
	if err != nil {
		t.Fatal(err)
	}

	if body != string(want) {
		t.Error("the template body is not the rendered template")
	}

	var tpl struct {
		Resources map[string]struct {
			Type       string
			Properties map[string]any
		}
	}

	if err := json.Unmarshal([]byte(body), &tpl); err != nil {
		t.Fatal(err)
	}

	for id, r := range tpl.Resources {
		if r.Type == "AWS::IAM::Role" && r.Properties["PermissionsBoundary"] == nil {
			t.Errorf("role %s has no boundary", id)
		}
	}
}

func TestNoDependencies(t *testing.T) {
	regs, err := run(t, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	if d := find(regs, "aws:cloudformation/stack:Stack")[0].dependencies; len(d) != 0 {
		t.Errorf("dependencies = %v", d)
	}
}

func TestNamesHook(t *testing.T) {
	regs, err := run(t, func(a *engine.Args) {
		a.Names = func(c engine.Child) string { return "toolkit-" + c.Qualifier + "-" + c.Account + "-" + c.Region }
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := find(regs, "aws:cloudformation/stack:Stack")[0].name; got != "toolkit-app-dev-eu-west-1" {
		t.Errorf("name = %q", got)
	}
}

func TestRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*engine.Args)
		want string
	}{
		"no account":   {func(a *engine.Args) { a.Account = "" }, "Account is empty"},
		"no region":    {func(a *engine.Args) { a.Region = "" }, "Region is empty"},
		"no partition": {func(a *engine.Args) { a.Partition = "" }, "Partition is empty"},
		"no provider":  {func(a *engine.Args) { a.Provider = nil }, "Provider is nil"},
		"bad bootstrap": {func(a *engine.Args) {
			a.Bootstrap.Qualifier = "Bad"
		}, "qualifier"},
		"account not bootstrapped": {func(a *engine.Args) { a.Account = "prod" }, "not in Bootstrap.Accounts"},
		"region not bootstrapped":  {func(a *engine.Args) { a.Region = "eu-north-1" }, "not in Bootstrap.Regions"},
		"empty name":               {func(a *engine.Args) { a.Names = func(engine.Child) string { return "" } }, "empty name"},
	} {
		t.Run(name, func(t *testing.T) {
			regs, err := run(t, tc.edit, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}

			if len(find(regs, "aws:cloudformation/stack:Stack")) != 0 || len(find(regs, engine.TypeToken)) != 0 {
				t.Error("something was registered before the refusal")
			}
		})
	}
}
