# Doctrine

This repository is held to the [component contract](https://github.com/truvity/policy/blob/master/docs/contracts/component.md);
this page says only what is particular to it and links there rather than
restating a rule.

## The organization is a file

An AWS organization is changed by clicking, and what was clicked is
recorded nowhere a reviewer reads. The registry is that record: one file,
reviewed like code, strictly loaded so that a typo is an error and not a
setting that quietly did nothing.

## Refuse first, apply second

Some resources hold state that lives outside any Pulumi stack: an account
holds everything running in it, an OU holds the accounts and policies under
it, a permission set holds its assignments. Replacing one "cleanly" is a
delete wearing a create's clothes, and the diff afterwards reads clean. The
guard belongs in front of the apply, as a preflight over the plan, because
`protect` stops deletes and not replaces. The same posture, and the same
reasoning, as [github-structure](https://github.com/truvity/github-structure).

## Look up what cannot be rebuilt

The organization itself is looked up in v1. There is nothing to adopt it
from, nothing to gain from managing it before the rest is proven, and a
replaced organization is not recoverable. Managing it is a later decision
with its own page.

## Dormant until it cannot lock you out

A service control policy can deny the very actions needed to remove it. v1
declares and validates policies and attaches none, until a check exists
that proves a change cannot cut off the principal that would repair it.

## Names are the caller's

Account names, emails, regions, groups and policies are inputs. The
components, when they land, name their children after what they are, and
those names are API because a URN is made of them.

## Nothing here touches a real account in CI

Tests parse text; the engine will run against Pulumi mocks. A test that
needs an account is a test that holds a credential, and a public
repository should hold none.
