#!/usr/bin/env bash
#
# Rotates the shared secret used for internal request signing.
#
# The new secret is generated locally, written to the platform secret store,
# and handed to the CLI by file reference.

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

# Files created by this script are readable only by their owner.
umask 077

readonly SECRET_BYTES=48
readonly REQUIRED_TOOLS=(aws jq openssl)

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
Usage: rotate-credentials.sh --secret-id <id> --region <region> [--dry-run]

  --secret-id   Identifier of the secret in the platform secret store.
  --region      Region the secret store lives in.
  --dry-run     Generate and validate, but do not write.
USAGE
  exit 2
}

require_tools() {
  local tool
  for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
  done
}

secret_id=""
region=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --secret-id)
      [[ $# -ge 2 ]] || usage
      secret_id="$2"
      shift 2
      ;;
    --region)
      [[ $# -ge 2 ]] || usage
      region="$2"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h | --help)
      usage
      ;;
    *)
      die "unrecognised argument: $1"
      ;;
  esac
done

[[ -n "$secret_id" ]] || usage
[[ -n "$region" ]] || usage

# Constrained here so that a typo fails early and loudly.
[[ "$secret_id" =~ ^[A-Za-z0-9/_.-]{1,512}$ ]] || die "secret id has an unexpected shape"
[[ "$region" =~ ^[a-z]{2}-[a-z]+-[0-9]$ ]] || die "region has an unexpected shape"

require_tools

workdir="$(mktemp -d)"
readonly workdir

cleanup() {
  # Overwrite before unlinking.
  if [[ -d "$workdir" ]]; then
    find "$workdir" -type f -exec shred --remove --zero {} + 2>/dev/null || true
    rm -rf -- "$workdir"
  fi
}
trap cleanup EXIT INT TERM

secret_file="$workdir/secret"

openssl rand -hex "$SECRET_BYTES" > "$secret_file"

# 48 bytes rendered as hex is 96 characters plus the trailing newline.
actual_length="$(wc -c < "$secret_file" | tr -d '[:space:]')"
[[ "$actual_length" == "$((SECRET_BYTES * 2 + 1))" ]] \
  || die "generated secret has unexpected length"

if [[ "$dry_run" == "true" ]]; then
  log "dry run: generated a ${SECRET_BYTES}-byte secret for '$secret_id'; not writing"
  exit 0
fi

log "writing new version of '$secret_id' in $region"

aws secretsmanager put-secret-value \
  --region "$region" \
  --secret-id "$secret_id" \
  --secret-string "file://$secret_file" \
  --output json \
  | jq -r '"created version " + .VersionId' >&2

log "rotation complete; restart consumers to pick up the new version"
