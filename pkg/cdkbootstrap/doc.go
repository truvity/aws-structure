// Package cdkbootstrap is the CDK bootstrap of an AWS CDK app, as data: the
// template CDK ships, the one transformation this estate makes to it, and the
// description of a bootstrap (Bootstrap) that pkg/engine/cdkbootstrap deploys.
//
// # One bootstrap per app
//
// A bootstrap is keyed by the CDK qualifier, which the app sets in its
// DefaultStackSynthesizer. Its roles and buckets are named "cdk-<qualifier>-*",
// so two apps in one account and region do not share them, and each app's
// bootstrap carries the permissions boundary of that app alone.
//
// # The template
//
// template/bootstrap-template.yaml is the file the aws-cdk npm package ships,
// copied byte for byte by hack/update-cdk-bootstrap.sh (which checks the
// tarball against the registry's integrity hash). template/VERSION is the
// aws-cdk release, tracked by Renovate; template/PROVENANCE records the tarball
// and the digest of the template, and a test refuses a template that is not the
// one PROVENANCE names. The template, LICENSE and NOTICE in that directory are
// the AWS CDK's, under the Apache License, Version 2.0.
//
// # The transformation
//
// CDK's template applies its InputPermissionsBoundary parameter to the
// CloudFormation execution role alone. The other roles it creates (file and
// image publishing, lookup, deployment action) get no boundary, so an account
// that refuses any role without one cannot be bootstrapped. Render copies the
// execution role's PermissionsBoundary, a condition on the parameter, onto
// every AWS::IAM::Role and AWS::IAM::User that has none, and returns the
// template as JSON. It refuses a template in which the execution role or its
// boundary is missing: that would be a change of CDK's template that must be
// read, not a template to deploy without a boundary.
package cdkbootstrap
