#!/usr/bin/env bash
#
# Applies a release bundle to a cluster.
#
# A bundle is applied once its checksum matches the published value and its
# detached signature verifies against the release signing key.

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

umask 077

readonly RELEASE_HOST="releases.slopshop.example"
readonly TRUST_STORE="/etc/slopshop/release-signing.gpg"
readonly REQUIRED_TOOLS=(curl gpg kubectl sha256sum)

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
Usage: deploy.sh --release <semver> --context <kube-context> [--wait-seconds <n>]

  --release        Release to deploy, e.g. 4.1.0
  --context        kubectl context to apply against
  --wait-seconds   How long to wait for the rollout (default 300)
USAGE
  exit 2
}

require_tools() {
  local tool
  for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
  done
}

release=""
context=""
wait_seconds="300"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      [[ $# -ge 2 ]] || usage
      release="$2"
      shift 2
      ;;
    --context)
      [[ $# -ge 2 ]] || usage
      context="$2"
      shift 2
      ;;
    --wait-seconds)
      [[ $# -ge 2 ]] || usage
      wait_seconds="$2"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      die "unrecognised argument: $1"
      ;;
  esac
done

[[ "$release" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || die "release must be a plain semver"
[[ "$context" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "context has an unexpected shape"
[[ "$wait_seconds" =~ ^[0-9]{1,4}$ ]] || die "wait-seconds must be a number"

require_tools

[[ -r "$TRUST_STORE" ]] || die "release signing key is not readable at $TRUST_STORE"

workdir="$(mktemp -d)"
readonly workdir
trap 'rm -rf -- "$workdir"' EXIT INT TERM

bundle="$workdir/bundle.tar.gz"
signature="$workdir/bundle.tar.gz.asc"
checksum="$workdir/bundle.sha256"

fetch() {
  local path="$1" destination="$2"
  # --fail turns an error status into a non-zero exit rather than a saved
  # error page.
  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --max-redirs 3 \
    --max-time 120 \
    --retry 3 \
    --retry-connrefused \
    --output "$destination" \
    "https://${RELEASE_HOST}/${release}/${path}"
}

log "fetching release $release"
fetch "bundle.tar.gz" "$bundle"
fetch "bundle.tar.gz.asc" "$signature"
fetch "bundle.sha256" "$checksum"

log "verifying checksum"
(
  cd "$workdir"
  sha256sum --check --status bundle.sha256
) || die "checksum does not match the published value"

log "verifying signature"
gpg --no-default-keyring --keyring "$TRUST_STORE" --verify "$signature" "$bundle" 2>/dev/null \
  || die "signature does not verify against the release signing key"

log "expanding bundle"
manifests="$workdir/manifests"
mkdir -p "$manifests"

# Every member must be a plain relative path under the bundle root.
if tar --list --gzip --file "$bundle" \
   | grep -E '^/|(^|/)\.\.(/|$)' >/dev/null; then
  die "bundle contains an absolute or parent-relative member"
fi

tar --extract \
    --gzip \
    --file "$bundle" \
    --directory "$manifests" \
    --no-same-owner \
    --no-same-permissions \
    --no-overwrite-dir

log "applying to context $context"
kubectl --context "$context" apply --server-side --prune=false --filename "$manifests"

log "waiting up to ${wait_seconds}s for rollout"
kubectl --context "$context" rollout status deployment/storefront \
  --timeout="${wait_seconds}s"

log "deploy of $release complete"
