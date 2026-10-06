package ssosync_test

import (
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"

	pulumiaws "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/aws-structure/pkg/ssosync"
)

type recorded struct {
	typ, name string
	inputs    resource.PropertyMap
}

type recorder struct {
	mu   sync.Mutex
	regs []recorded
}

func (r *recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.regs = append(r.regs, recorded{args.TypeToken, args.Name, args.Inputs})
	r.mu.Unlock()

	out := args.Inputs.Copy()
	out["arn"] = resource.NewProperty("arn-of-" + args.Name)

	return args.Name + "-id", out, nil
}

func (*recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token == "aws:ssm/getParameter:getParameter" {
		return resource.PropertyMap{
			"name":  args.Args["name"],
			"value": resource.NewProperty("value-of-" + args.Args["name"].StringValue()),
		}, nil
	}

	return resource.PropertyMap{}, nil
}

func args(p *pulumiaws.Provider) ssosync.Args {
	return ssosync.Args{
		Provider:          p,
		Partition:         "part",
		Version:           "1.2.3",
		LambdaBucket:      "bucket-ref",
		LambdaKey:         "key-ref",
		SCIMEndpointParam: "/scim/endpoint",
		SCIMTokenParam:    "/scim/token",
		Google:            ssosync.GoogleCredentials{AdminEmail: "admin@example.test", CustomerID: "customer-ref", KeyJSON: "{}"},
		GroupMatch:        "email:group-*",
	}
}

func TestDeployNamesAndEnvironment(t *testing.T) {
	rec := &recorder{}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := pulumiaws.NewProvider(ctx, "p", &pulumiaws.ProviderArgs{Region: pulumi.String("region-a")})
		if err != nil {
			return err
		}

		return ssosync.Deploy(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), args(p))
	}, pulumi.WithMocks("proj", "stack", rec))
	if err != nil {
		t.Fatal(err)
	}

	var got []string

	for _, g := range rec.regs {
		if g.typ != "pulumi:providers:aws" && g.typ != "pulumi:pulumi:Stack" {
			got = append(got, g.name)
		}
	}

	sort.Strings(got)

	want := []string{
		"ssosync-lambda", "ssosync-lambda-basic", "ssosync-lambda-role", "ssosync-lambda-sso-policy",
		"ssosync-log-group", "ssosync-schedule", "ssosync-scheduler-invoke-policy", "ssosync-scheduler-role",
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names:\n got %v\nwant %v", got, want)
	}

	for _, g := range rec.regs {
		if g.name != "ssosync-lambda" {
			continue
		}

		env := g.inputs["environment"].ObjectValue()["variables"].ObjectValue()
		if env["GROUP_MATCH"].StringValue() != "email:group-*" || env["SCIM_ENDPOINT"].StringValue() != "value-of-/scim/endpoint" {
			t.Errorf("environment = %v", env)
		}
	}
}

func TestDeployRefusals(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		return ssosync.Deploy(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), ssosync.Args{})
	}, pulumi.WithMocks("proj", "stack", &recorder{}))
	if err == nil || !strings.Contains(err.Error(), "Provider is nil") || !strings.Contains(err.Error(), "GroupMatch is empty") {
		t.Fatalf("empty args not refused together: %v", err)
	}
}
