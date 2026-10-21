// Package cdkbootstrap deploys the CDK bootstrap of one app in one account and
// region as one Pulumi ComponentResource, truvity:aws-structure:CDKBootstrap.
//
// It creates one CloudFormation stack, "CDKToolkit-<qualifier>", from the
// template pkg/cdkbootstrap renders (CDK's own bootstrap template with the
// app's permissions boundary on every role). The stack's parameters are the
// qualifier, the boundary's name, the execution policies and the trusted
// accounts of the pkg/cdkbootstrap.Bootstrap. The stack is created with
// CAPABILITY_NAMED_IAM: its roles are named "cdk-<qualifier>-*".
//
// The caller supplies the AWS provider of the account and region, and the
// resources the stack needs first (DependsOn): the boundary policy must exist
// in the account before the stack creates a role under it. The component never
// falls back to a default provider.
//
// Deleting the stack deletes its roles and keeps the staging bucket and the
// container repository (CDK sets their DeletionPolicy to Retain); a bootstrap
// created again after a delete needs the bucket removed first.
//
// See docs/reference.md for the child, its name and the inputs.
package cdkbootstrap
