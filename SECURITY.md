# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/aws-structure/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| older   | no        |

## Design notes relevant to a reviewer

- This module describes who may do what across an AWS organization, so a
  default is a security surface. It ships no default that widens access:
  service control policies are dormant (`scp_enforcement` defaults to
  `dormant` and `enforced` is refused), and every region, principal and
  policy document is an input.
- The organization is looked up, never created, modified or deleted, by
  this module in v1.
- It holds no credentials. AWS credentials belong to the Pulumi program
  that will call the engine; the registry parser reads a file and nothing
  else, and no credential belongs in a registry file.
- Policy documents in a registry are validated as JSON and against AWS's
  size limits, not for what they allow. Reviewing what a policy permits is
  the reviewer's job.
- Tests parse text and never touch an AWS account, so no test credential
  exists to leak. The identifiers in tests are documentation placeholders.
