package ssosync

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/scheduler"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ssm"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// GoogleCredentials are the Google Workspace service account credentials the
// sync runs with.
type GoogleCredentials struct {
	// AdminEmail is the domain-wide delegation admin.
	AdminEmail string
	// CustomerID is the Workspace customer id.
	CustomerID string
	// KeyJSON is the service account's private key JSON. It is passed to the
	// Lambda as a secret.
	KeyJSON string
}

// Args configures Deploy.
type Args struct {
	// Provider is the AWS provider of the account and region Identity Center
	// lives in. Required.
	Provider *aws.Provider
	// Partition is the ARN partition, for the AWS managed policy attached to
	// the Lambda role. Required.
	Partition string
	// Version is the ssosync release the artifact was built from. It is only
	// logged. Required.
	Version string
	// LambdaBucket and LambdaKey locate the Lambda's zip (linux, arm64,
	// provided.al2023). Required.
	LambdaBucket string
	LambdaKey    string
	// SCIMEndpointParam and SCIMTokenParam are the SSM Parameter Store names of
	// the SCIM endpoint and access token (SecureString, populated by hand). They
	// are read at preview and deploy and passed to the Lambda; the token as a
	// secret. Required.
	SCIMEndpointParam string
	SCIMTokenParam    string
	// Google are the Workspace credentials. Required.
	Google GoogleCredentials
	// GroupMatch is the Google Admin SDK group query. The sync runs one list
	// call per comma-separated query and unions the results, so a migration's
	// dual-run window is extra entries here, never a code change. Required.
	GroupMatch string
}

// Validate reports every problem with a at once, or returns nil.
func (a *Args) Validate() error {
	var errs []error

	if a.Provider == nil {
		errs = append(errs, errors.New("args: Provider is nil"))
	}

	for name, v := range map[string]string{
		"Partition": a.Partition, "Version": a.Version, "LambdaBucket": a.LambdaBucket, "LambdaKey": a.LambdaKey,
		"SCIMEndpointParam": a.SCIMEndpointParam, "SCIMTokenParam": a.SCIMTokenParam, "GroupMatch": a.GroupMatch,
		"Google.AdminEmail": a.Google.AdminEmail, "Google.CustomerID": a.Google.CustomerID, "Google.KeyJSON": a.Google.KeyJSON,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("args: %s is empty", name))
		}
	}

	return errors.Join(errs...)
}

// Deploy deploys the ssosync Lambda: an IAM role, a log group, the function, an
// EventBridge schedule that runs it every 15 minutes and the role the schedule
// assumes. Google credentials come in through Args; the SCIM endpoint and token
// are read from SSM Parameter Store.
func Deploy(ctx *pulumi.Context, logger *slog.Logger, a Args) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("ssosync: %w", err)
	}

	goCtx := ctx.Context()
	provider := a.Provider

	logger.InfoContext(goCtx, "deploying ssosync Lambda infrastructure", slog.String("group_match", a.GroupMatch))

	// ── SSM: SCIM endpoint + token (pre-populated manually) ──────────────
	withDecryption := true

	scimEndpointParam, err := ssm.LookupParameter(ctx, &ssm.LookupParameterArgs{
		Name:           a.SCIMEndpointParam,
		WithDecryption: &withDecryption,
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("lookup SSM %s: %w", a.SCIMEndpointParam, err)
	}

	scimTokenParam, err := ssm.LookupParameter(ctx, &ssm.LookupParameterArgs{
		Name:           a.SCIMTokenParam,
		WithDecryption: &withDecryption,
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("lookup SSM %s: %w", a.SCIMTokenParam, err)
	}

	// ── IAM role ─────────────────────────────────────────────────────────
	lambdaRole, err := iam.NewRole(ctx, "ssosync-lambda-role", &iam.RoleArgs{
		Name: pulumi.String("ssosync"),
		AssumeRolePolicy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Action": "sts:AssumeRole",
				"Effect": "Allow",
				"Principal": {"Service": "lambda.amazonaws.com"}
			}]
		}`),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create Lambda IAM role: %w", err)
	}

	_, err = iam.NewRolePolicyAttachment(ctx, "ssosync-lambda-basic", &iam.RolePolicyAttachmentArgs{
		Role:      lambdaRole.Name,
		PolicyArn: pulumi.Sprintf("arn:%s:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole", a.Partition),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("attach basic execution policy: %w", err)
	}

	// ssosync calls ssoadmin:ListInstances to resolve IdentityStoreID at runtime.
	// It also calls identitystore:* for SCIM-based group/user sync.
	_, err = iam.NewRolePolicy(ctx, "ssosync-lambda-sso-policy", &iam.RolePolicyArgs{
		Role: lambdaRole.Name,
		Policy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"sso:ListInstances",
					"identitystore:*"
				],
				"Resource": "*"
			}]
		}`),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create SSO inline policy: %w", err)
	}

	// ── CloudWatch Log Group ─────────────────────────────────────────────
	logGroup, err := cloudwatch.NewLogGroup(ctx, "ssosync-log-group", &cloudwatch.LogGroupArgs{
		Name:            pulumi.String("/aws/lambda/ssosync"),
		RetentionInDays: pulumi.Int(14),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create log group: %w", err)
	}

	// Deploy Lambda, schedule, and trigger invocation.
	if err := deployLambda(ctx, logger, &a, lambdaRole, logGroup, scimEndpointParam.Value, scimTokenParam.Value); err != nil {
		return err
	}

	logger.InfoContext(goCtx, "ssosync infrastructure deployed")

	return nil
}

// deployLambda creates the Lambda function, the EventBridge schedule, and
// leaves invocation to the schedule.
func deployLambda(
	ctx *pulumi.Context,
	logger *slog.Logger,
	a *Args,
	lambdaRole *iam.Role,
	logGroup *cloudwatch.LogGroup,
	scimEndpoint string,
	scimToken string,
) error {
	goCtx := ctx.Context()
	provider := a.Provider

	lambdaFn, err := lambda.NewFunction(ctx, "ssosync-lambda", &lambda.FunctionArgs{
		Name:    pulumi.String("ssosync"),
		Role:    lambdaRole.Arn,
		Runtime: pulumi.String("provided.al2023"),
		Architectures: pulumi.StringArray{
			pulumi.String("arm64"),
		},
		Handler:    pulumi.String("bootstrap"),
		Timeout:    pulumi.Int(300),
		MemorySize: pulumi.Int(256),
		S3Bucket:   pulumi.String(a.LambdaBucket),
		S3Key:      pulumi.String(a.LambdaKey),
		LoggingConfig: &lambda.FunctionLoggingConfigArgs{
			LogGroup:  logGroup.Name,
			LogFormat: pulumi.String("JSON"),
		},
		Environment: &lambda.FunctionEnvironmentArgs{
			Variables: pulumi.StringMap{
				// ssosync Lambda mode reads env vars WITHOUT the SSOSYNC_ prefix.
				// See configLambda() in cmd/root.go.
				"LOG_LEVEL":          pulumi.String("info"),
				"LOG_FORMAT":         pulumi.String("json"),
				"SYNC_METHOD":        pulumi.String("groups"),
				"GOOGLE_ADMIN":       pulumi.String(a.Google.AdminEmail),
				"GOOGLE_CREDENTIALS": pulumi.ToSecret(pulumi.String(a.Google.KeyJSON)).(pulumi.StringOutput),
				"CUSTOMER_ID":        pulumi.String(a.Google.CustomerID),
				"SCIM_ENDPOINT":      pulumi.String(scimEndpoint),
				"SCIM_ACCESS_TOKEN":  pulumi.ToSecret(pulumi.String(scimToken)).(pulumi.StringOutput),
				"GROUP_MATCH":        pulumi.String(a.GroupMatch),
			},
		},
	}, pulumi.Provider(provider), pulumi.DependsOn([]pulumi.Resource{logGroup}))
	if err != nil {
		return fmt.Errorf("create Lambda function: %w", err)
	}

	logger.InfoContext(goCtx, "created ssosync Lambda", slog.String("version", a.Version))

	// ── EventBridge Scheduler ────────────────────────────────────────────
	schedulerRole, err := iam.NewRole(ctx, "ssosync-scheduler-role", &iam.RoleArgs{
		Name: pulumi.String("ssosync-scheduler"),
		AssumeRolePolicy: pulumi.String(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Action": "sts:AssumeRole",
				"Effect": "Allow",
				"Principal": {"Service": "scheduler.amazonaws.com"}
			}]
		}`),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create scheduler IAM role: %w", err)
	}

	_, err = iam.NewRolePolicy(ctx, "ssosync-scheduler-invoke-policy", &iam.RolePolicyArgs{
		Role: schedulerRole.Name,
		Policy: lambdaFn.Arn.ApplyT(func(arn string) (string, error) {
			policy := map[string]any{
				"Version": "2012-10-17",
				"Statement": []map[string]any{{
					"Effect":   "Allow",
					"Action":   "lambda:InvokeFunction",
					"Resource": arn,
				}},
			}

			data, err := json.Marshal(policy)
			if err != nil {
				return "", fmt.Errorf("marshal scheduler policy: %w", err)
			}

			return string(data), nil
		}).(pulumi.StringOutput),
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create scheduler invoke policy: %w", err)
	}

	_, err = scheduler.NewSchedule(ctx, "ssosync-schedule", &scheduler.ScheduleArgs{
		Name:               pulumi.String("ssosync-every-15min"),
		ScheduleExpression: pulumi.String("rate(15 minutes)"),
		FlexibleTimeWindow: &scheduler.ScheduleFlexibleTimeWindowArgs{
			Mode: pulumi.String("OFF"),
		},
		Target: &scheduler.ScheduleTargetArgs{
			Arn:     lambdaFn.Arn,
			RoleArn: schedulerRole.Arn,
		},
	}, pulumi.Provider(provider))
	if err != nil {
		return fmt.Errorf("create EventBridge schedule: %w", err)
	}

	// NOTE: lambda.Invocation was removed — it only runs on CREATE and caused
	// deploy failures when ssosync couldn't reach SCIM on first attempt.
	// The EventBridge schedule (every 15 min) handles ongoing sync.

	logger.InfoContext(goCtx, "ssosync Lambda deployed with schedule")

	ctx.Export("ssosync_lambda_arn", lambdaFn.Arn)

	return nil
}
