# 0003 — Bootstrap: user-data is composed from fragments, as cloud-init

**Status:** Accepted

## Context

An instance that joins a fleet needs packages, files, digest-pinned
binaries, systemd units and a secret or two. Each consumer wrote its own
user-data script. Scripts cannot be merged, so two concerns on one machine
meant copy-paste, and nothing stopped a token being pasted into user-data,
which anyone who can describe the instance can read. EC2 user-data is also
limited to 16 KiB.

## Decision

1. **cloud-init, everywhere.** The output is a `#cloud-config`, because
   cloud-init already has the vocabulary (`packages`, `write_files`,
   `bootcmd`, `runcmd`) and reads gzip user-data natively.
2. **The fragment type is defined here, in cloud-init terms.** A component
   that knows how to install a service (`truvity/edge`'s `instanceconnector`)
   exposes plain data and the consumer adapts it (`UnitFragment` has the same
   field set, so that is a field copy). This module does not import
   `truvity/edge` and `edge` does not import this module.
3. **Refusals instead of conventions.** Two fragments writing one path or
   unit, secret material in any content, a download without https and a
   sha256, and user-data over the hard limit are errors at plan time rather
   than a machine that boots wrong. The secret check is a tripwire for the
   accident, not a proof; the supported path is `SSMSecret`, whose value never
   reaches the user-data and whose parameter name is collected for the role
   policy.
4. **Size is handled in a fixed order.** Gzip past the soft limit, then
   content-addressed S3 objects for `DeliveryAuto` files, largest first, then
   an error past the hard limit. Objects are keyed by sha256, so an upload
   never replaces different bytes and a re-render of unchanged content is the
   same key. The caller uploads; this module has no cloud dependency.
5. **Failure is closed.** Generated steps run under `bash -ec` after a
   `set -e`; with a lifecycle hook configured a failed download abandons the
   hook so the group replaces the instance.
6. **Secrets load on every boot.** A secret lands under `/run`, which is
   empty after every stop and start, and both appliances use warm pools, where
   a resume is a reboot. `cloud-init` runs `runcmd` once and `bootcmd` before
   the network, so neither can do it. The composer instead writes a loader
   script and a oneshot unit, `bootstrap-secrets.service`, ordered after
   `network-online.target` and before the consumers, which get a drop-in that
   requires it. The first-boot lifecycle action is abandoned on failure; a
   resumed boot has none pending, so the instance is reported unhealthy
   instead (`set-instance-health`), and the group replaces it. A first-boot
   only load is an explicit opt-in (`FirstBootOnly`), and a `File` or
   `Artifact` under `/run` is refused.
7. **Verbatim is a separate path.** A consumer adopting the package first
   passes its existing user-data through `Verbatim` (byte-identical output,
   so the plan shows no diff) and moves pieces into fragments one at a time.

## Roads not taken

- A fragment interface that edge implements: would make one module import the
  other.
- A shared helper script on the instance (`write_files` of a library each
  step sources): saves bytes but makes every step depend on a file written
  earlier, which `bootcmd` runs before. Each generated step carries its own
  small prelude instead; gzip removes most of the repetition.
- Loading secrets in `bootcmd` (every boot): it runs before the network and
  before the aws CLI is installed on a first boot.
- A scanner heuristic for `password = value` assignments: too many false
  positives in ordinary scripts for a check with no override.

## Consequences

Additive. `Render` is deterministic, so a checked-in golden of a consumer's
user-data is a review artifact.
