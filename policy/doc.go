// Package policy is a typed model of an IAM policy document, for the
// documents a program writes by hand: permissions boundaries first of all.
//
// A component that needs a boundary returns a [Document]; the system that
// creates the boundaries appends its own statements, checks the size, and
// marshals. Nothing here talks to AWS, and the module has no dependencies
// beyond the standard library.
//
// # Canonical JSON
//
// [Document.MarshalJSON] is canonical: the same document always produces the
// same bytes, so a document can be compared, hashed and diffed.
//
//   - Version defaults to "2012-10-17".
//   - The fields of a statement come in the order IAM documentation uses: Sid,
//     Effect, Action, NotAction, Resource, NotResource, Condition. An empty
//     list is left out.
//   - A list that holds one value is written as the bare string, as IAM
//     documents usually are. [Statement.Arrays] and [Condition.Array] keep
//     such a list an array. IAM reads both forms alike, but a document that
//     already exists in an account is compared by its bytes, so a rendering
//     that must not change keeps the form it has. [Document.UnmarshalJSON]
//     sets the flags where it reads a one-element array, so a document read
//     and written again is byte-identical.
//   - The conditions of a statement are grouped by operator, then by key,
//     both in byte order, as IAM writes them.
//   - The output is minified and escaped as encoding/json escapes strings.
//
// # What the model leaves out
//
// Principal and NotPrincipal (an identity policy and a boundary have none),
// Id, and condition values that are not strings. [Document.UnmarshalJSON]
// refuses a document that uses them rather than drop them.
package policy
