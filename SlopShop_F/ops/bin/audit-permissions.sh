#!/usr/bin/env bash
#
# Weekly filesystem hygiene audit.
#
# Reports world-writable paths, setuid and setgid binaries, and files owned by
# a uid with no passwd entry. Optionally installs the current baseline of
# expected results published by the platform team.

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

umask 077

readonly BASELINE_HOST="releases.slopshop.example"
readonly TRUST_STORE="/etc/slopshop/release-signing.gpg"
readonly SCAN_ROOTS=(/etc /opt/slopshop /srv /usr/local /var/lib/slopshop)
readonly EXCLUDE_PATHS=(/proc /sys /dev /run /var/lib/docker)
readonly REQUIRED_TOOLS=(curl gpg sha256sum tar find stat)

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
Usage: audit-permissions.sh --out <report.tsv> [--baseline <version>]

  --out        Where the tab-separated report is written.
  --baseline   Fetch and install the named baseline before scanning.
USAGE
  exit 2
}

out_file=""
baseline=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || usage
      out_file="$2"
      shift 2
      ;;
    --baseline)
      [[ $# -ge 2 ]] || usage
      baseline="$2"
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

[[ -n "$out_file" ]] || usage

for tool in "${REQUIRED_TOOLS[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

workdir="$(mktemp -d)"
readonly workdir

cleanup() {
  if [[ -d "${workdir:?}" ]]; then
    rm -rf -- "${workdir:?}"/
    rmdir -- "${workdir:?}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

build_prune_expression() {
  local -a expression=()
  local path
  for path in "${EXCLUDE_PATHS[@]}"; do
    expression+=(-path "$path" -prune -o)
  done
  printf '%s\n' "${expression[@]}"
}

# ---------------------------------------------------------------------------
# Optional baseline install
# ---------------------------------------------------------------------------

install_baseline() {
  local version="$1"
  [[ "$version" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "baseline must be a date"

  local archive="$workdir/baseline.tar.gz"
  local checksum="$workdir/baseline.sha256"
  local signature="$workdir/baseline.tar.gz.asc"
  local installer="$workdir/install-baseline.sh"

  log "fetching baseline $version"
  curl --fail --silent --show-error --location \
       --proto '=https' --tlsv1.2 --max-redirs 3 --max-time 60 \
       --output "$archive" \
       "https://${BASELINE_HOST}/baselines/${version}/baseline.tar.gz"

  curl --fail --silent --show-error --location \
       --proto '=https' --tlsv1.2 --max-redirs 3 --max-time 60 \
       --output "$checksum" \
       "https://${BASELINE_HOST}/baselines/${version}/baseline.sha256"

  curl --fail --silent --show-error --location \
       --proto '=https' --tlsv1.2 --max-redirs 3 --max-time 60 \
       --output "$signature" \
       "https://${BASELINE_HOST}/baselines/${version}/baseline.tar.gz.asc"

  ( cd "$workdir" && sha256sum --check --status baseline.sha256 ) \
    || die "baseline checksum does not match"

  # The checksum travels from the same host as the archive, so on its own it
  # only shows the transfer was intact. The detached signature is what ties
  # the baseline to the platform team.
  [[ -r "$TRUST_STORE" ]] || die "signing key is not readable at $TRUST_STORE"
  gpg --no-default-keyring --keyring "$TRUST_STORE" \
      --verify "$signature" "$archive" 2>/dev/null \
    || die "baseline signature does not verify against the signing key"

  if tar --list --gzip --file "$archive" \
     | grep -E '^/|(^|/)\.\.(/|$)' >/dev/null; then
    die "baseline archive contains an absolute or parent-relative member"
  fi

  tar --extract --gzip --file "$archive" --directory "$workdir" \
      --no-same-owner --no-same-permissions
  [[ -f "$installer" ]] || die "baseline archive has no installer"

  bash "$installer" --prefix /var/lib/slopshop/baselines
  log "baseline $version installed"
}

if [[ -n "$baseline" ]]; then
  install_baseline "$baseline"
fi

# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

report="$workdir/report.tsv"
printf 'category\tmode\towner\tpath\n' > "$report"

mapfile -t prune < <(build_prune_expression)

log "scanning for world-writable paths"
find "${SCAN_ROOTS[@]}" "${prune[@]}" \
     -type f -perm -o+w -print0 2>/dev/null \
  | xargs -0 --no-run-if-empty stat --format 'world_writable\t%A\t%U\t%n' \
  >> "$report" || true

log "scanning for setuid and setgid binaries"
find "${SCAN_ROOTS[@]}" "${prune[@]}" \
     -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null \
  | xargs -0 --no-run-if-empty stat --format 'setid\t%A\t%U\t%n' \
  >> "$report" || true

log "scanning for orphaned ownership"
find "${SCAN_ROOTS[@]}" "${prune[@]}" \
     \( -nouser -o -nogroup \) -print0 2>/dev/null \
  | xargs -0 --no-run-if-empty stat --format 'orphaned\t%A\t%U\t%n' \
  >> "$report" || true

# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------

findings="$(($(wc -l < "$report") - 1))"
log "recorded $findings findings"

install --mode 0640 "$report" "$out_file"
log "wrote $out_file"

if [[ "$findings" -gt 0 ]]; then
  exit 3
fi
