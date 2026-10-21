package cdkbootstrap_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/truvity/aws-structure/pkg/cdkbootstrap"
)

// A template written with short-form tags is the same template as one written
// with the long form.
func TestShortFormTagsEqualLongForm(t *testing.T) {
	short := `
Parameters:
  Boundary:
    Type: String
Conditions:
  Set: !Not [!Equals [!Ref Boundary, '']]
Resources:
  CloudFormationExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub cdk-${Boundary}-exec
      PermissionsBoundary: !If
        - Set
        - !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/${Boundary}'
        - !Ref AWS::NoValue
  Other:
    Type: AWS::IAM::Role
    Properties:
      Description: !Join ['', [a, !GetAtt CloudFormationExecutionRole.Arn]]
`
	long := `
Parameters:
  Boundary:
    Type: String
Conditions:
  Set:
    Fn::Not:
      - Fn::Equals:
          - Ref: Boundary
          - ''
Resources:
  CloudFormationExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName:
        Fn::Sub: cdk-${Boundary}-exec
      PermissionsBoundary:
        Fn::If:
          - Set
          - Fn::Sub: 'arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/${Boundary}'
          - Ref: AWS::NoValue
  Other:
    Type: AWS::IAM::Role
    Properties:
      Description:
        Fn::Join:
          - ''
          - - a
            - Fn::GetAtt:
                - CloudFormationExecutionRole
                - Arn
`

	a, err := cdkbootstrap.Transform([]byte(short))
	if err != nil {
		t.Fatal(err)
	}

	b, err := cdkbootstrap.Transform([]byte(long))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(decodeJSON(t, a), decodeJSON(t, b)) {
		t.Errorf("short form and long form differ:\n%s\n%s", a, b)
	}

	other := resources(t, decodeJSON(t, a))["Other"]["Properties"].(map[string]any)
	if other["PermissionsBoundary"] == nil {
		t.Error("the second role did not get the boundary")
	}
}

func TestTransformRefusesWithoutExecutionBoundary(t *testing.T) {
	for name, tpl := range map[string]struct{ yaml, want string }{
		"no execution role": {
			"Resources:\n  A:\n    Type: AWS::IAM::Role\n    Properties: {}\n",
			"no CloudFormationExecutionRole",
		},
		"execution role without a boundary": {
			"Resources:\n  CloudFormationExecutionRole:\n    Type: AWS::IAM::Role\n    Properties:\n      RoleName: x\n",
			"has no PermissionsBoundary",
		},
		"execution role without properties": {
			"Resources:\n  CloudFormationExecutionRole:\n    Type: AWS::IAM::Role\n",
			"has no PermissionsBoundary",
		},
		"null boundary": {
			"Resources:\n  CloudFormationExecutionRole:\n    Type: AWS::IAM::Role\n    Properties:\n      PermissionsBoundary: ~\n",
			"has no PermissionsBoundary",
		},
		"execution role is not a role": {
			"Resources:\n  CloudFormationExecutionRole:\n    Type: AWS::S3::Bucket\n    Properties:\n      PermissionsBoundary: x\n",
			"is not an AWS::IAM::Role",
		},
		"no resources":  {"Description: x\n", "no Resources"},
		"two documents": {"Resources: {}\n---\nResources: {}\n", "more than one"},
		"not a mapping": {"- a\n", "not a mapping"},
		"repeated key":  {"Resources: {}\nResources: {}\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cdkbootstrap.Transform([]byte(tpl.yaml))
			if err == nil {
				t.Fatal("Transform accepted the template")
			}

			if !strings.Contains(err.Error(), tpl.want) {
				t.Errorf("error = %v, want it to contain %q", err, tpl.want)
			}
		})
	}
}

func TestTransformKeepsAnExistingBoundaryAndCoversUsers(t *testing.T) {
	out, err := cdkbootstrap.Transform([]byte(`
Resources:
  CloudFormationExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      PermissionsBoundary: exec
  Own:
    Type: AWS::IAM::Role
    Properties:
      PermissionsBoundary: own
  Bare:
    Type: AWS::IAM::Role
  User:
    Type: AWS::IAM::User
    Properties:
      UserName: u
  Bucket:
    Type: AWS::S3::Bucket
`))
	if err != nil {
		t.Fatal(err)
	}

	res := resources(t, decodeJSON(t, out))

	got := map[string]any{}

	for id, r := range res {
		if p, ok := r["Properties"].(map[string]any); ok {
			got[id] = p["PermissionsBoundary"]
		}
	}

	want := map[string]any{"CloudFormationExecutionRole": "exec", "Own": "own", "Bare": "exec", "User": "exec", "Bucket": nil}
	// The bucket has no Properties at all: it must not have grown any.
	delete(want, "Bucket")

	if !reflect.DeepEqual(got, want) {
		t.Errorf("boundaries = %v, want %v", got, want)
	}

	if _, ok := res["Bucket"]["Properties"]; ok {
		t.Error("a bucket gained Properties")
	}
}

func TestOutputIsNotHTMLEscaped(t *testing.T) {
	out, err := cdkbootstrap.Render()
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(out), `\u0026`) || strings.Contains(string(out), `\u003c`) {
		t.Error("the JSON is HTML-escaped")
	}
}
