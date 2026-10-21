# policy

A typed model of an IAM policy document, for documents a program writes by
hand: permissions boundaries first of all. Standard library only.

```sh
go get github.com/truvity/aws-structure/policy
```

The module is versioned by its own tags, `policy/vX.Y.Z`.

```go
d := policy.Document{Statement: []policy.Statement{
    {Sid: "AllowAll", Effect: policy.Allow, Action: []string{"*"}, Resource: []string{"*"}},
    {
        Sid: "DenyUntaggedCreate", Effect: policy.Deny, Action: []string{"iam:CreateRole"}, Resource: []string{"*"},
        Condition: []policy.Condition{{Operator: "Null", Key: "aws:RequestTag/project", Values: []string{"true"}}},
    },
}}

if err := d.Validate(); err != nil { /* every problem, at once */ }

n, _ := d.Size()          // minified characters; IAM allows 6,144 in a managed policy
b, _ := json.Marshal(d)   // canonical, minified
```

## Why it exists

A component owns the shape of its permissions boundary, and the system that
creates the boundaries owns the safety statements every boundary carries.
Passing a JSON string between them lets neither check anything. A
`policy.Document` can be validated, measured, appended to and compared
without parsing.

## Canonical JSON

`json.Marshal` of a `Document` always writes the same bytes for the same
document:

- `Version` defaults to `2012-10-17`.
- Statement fields come in the order of the IAM documentation: `Sid`,
  `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Condition`.
  An empty list is left out.
- A list of one value is written as the bare string.
  `Statement.Arrays` (and `Condition.Array`) keep it an array. IAM reads both
  forms alike, but a document that already exists in an account is compared
  by its bytes, so a rendering that must not change keeps its form.
- Conditions are grouped by operator, then by key, in byte order.
- Output is minified and escaped as `encoding/json` escapes strings.

Reading is the inverse: a string where a list may stand is a list of one, and
a one-element array sets the `Arrays` flag, so reading a document and writing
it again gives the same bytes. The reader refuses what the model leaves out
(`Principal`, `NotPrincipal`, `Id`, a condition value that is not a string)
with an error wrapping `policy.ErrUnsupported`.

## Validation

`Document.Validate` checks, and reports all problems together:

- `Version` is empty or `2012-10-17`; there is at least one statement;
- every statement has a `Sid` of ASCII letters and digits, unique in the
  document, and an `Effect` of `Allow` or `Deny`;
- exactly one of `Action` and `NotAction`, and exactly one of `Resource` and
  `NotResource`;
- no empty string in a list;
- every condition has an operator, a key and a value, and no operator and key
  appear twice in a statement.

`MarshalJSON` fails only where a document cannot be written (two conditions on
one operator and key); it does not validate the rest.
