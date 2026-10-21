#!/usr/bin/env bash
# Vendors CDK's bootstrap template from the aws-cdk npm package.
#
#   hack/update-cdk-bootstrap.sh [version]
#
# The version defaults to the one in pkg/cdkbootstrap/template/VERSION, which
# Renovate keeps current (renovate.json, "customManagers"). A Renovate pull
# request moves VERSION only; run this script on its branch to fetch the
# template that version ships, and review the diff of the template: it is the
# stack that is deployed to the accounts that carry a bootstrap.
#
# The template is copied byte for byte. The tarball is checked against the
# integrity (sha512) the registry publishes for that version before anything
# is extracted. Needs: curl, jq, openssl, tar.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$root/pkg/cdkbootstrap/template"
version="${1:-$(tr -d '[:space:]' <"$dir/VERSION")}"

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "update-cdk-bootstrap: version '$version' is not X.Y.Z" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

registry="https://registry.npmjs.org/aws-cdk/$version"
curl -fsSL --max-time 60 "$registry" -o "$work/meta.json"

tarball="$(jq -er '.dist.tarball' "$work/meta.json")"
integrity="$(jq -er '.dist.integrity' "$work/meta.json")"

case "$integrity" in
  sha512-*) ;;
  *) echo "update-cdk-bootstrap: registry integrity '$integrity' is not sha512" >&2; exit 1 ;;
esac

curl -fsSL --max-time 300 "$tarball" -o "$work/aws-cdk.tgz"

got="sha512-$(openssl dgst -sha512 -binary "$work/aws-cdk.tgz" | base64 -w0)"
if [ "$got" != "$integrity" ]; then
  echo "update-cdk-bootstrap: integrity mismatch: registry says $integrity, tarball is $got" >&2
  exit 1
fi

mkdir "$work/x"
tar -xzf "$work/aws-cdk.tgz" -C "$work/x" \
  package/lib/api/bootstrap/bootstrap-template.yaml package/LICENSE package/NOTICE

install -m 0644 "$work/x/package/lib/api/bootstrap/bootstrap-template.yaml" "$dir/bootstrap-template.yaml"
install -m 0644 "$work/x/package/LICENSE" "$dir/LICENSE"
install -m 0644 "$work/x/package/NOTICE" "$dir/NOTICE"

printf '%s\n' "$version" >"$dir/VERSION"
{
  echo "aws-cdk $version"
  echo "$tarball"
  echo "$integrity"
  echo "sha256-$(openssl dgst -sha256 -binary "$dir/bootstrap-template.yaml" | base64 -w0)"
} >"$dir/PROVENANCE"

echo "vendored the bootstrap template of aws-cdk $version"
