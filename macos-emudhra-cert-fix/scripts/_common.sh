# shellcheck shell=bash
# Shared helpers for the eMudhra cert.pem remediation scripts.
# Source of truth: https://support.apple.com/en-us/149555 (published 2026-10-23).
# Compatible with the stock macOS /bin/bash (3.2) on Intel and Apple silicon.

set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
umask 022

readonly CERT_FILE=/etc/ssl/cert.pem
readonly BACKUP_FILE=/etc/ssl/cert.pem.orig
readonly OPENSSL=/usr/bin/openssl

# Exact header lines from Apple's article (step 2 and step 3).
readonly EMSIGN_HEADER='=== /C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3'
readonly AAA_HEADER='=== /C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services'
readonly EMSIGN_CN='emSign ECC Root CA - G3'
readonly AAA_CN='AAA Certificate Services'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

# The blocked intermediate certificates (SHA-256 fingerprints from Apple's article).
BLOCKED_CERTS_FILE="$(cd "$SCRIPT_DIR/.." && pwd -P)/data/blocked-certificates.txt"
readonly BLOCKED_CERTS_FILE

info() { printf '[INFO]  %s\n' "$*"; }
ok()   { printf '[OK]    %s\n' "$*"; }
warn() { printf '[WARN]  %s\n' "$*"; }
err()  { printf '[ERROR] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }

require_macos() {
  [ "$(uname -s)" = "Darwin" ] || die "This script only supports macOS."
  [ -x "$OPENSSL" ] || die "$OPENSSL not found."
}

# Prints the exact command the user should run, then exits, if not root.
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This script modifies $CERT_FILE and must run as root."
    printf '\nRun this single command in Terminal:\n\n  sudo %s/%s\n\n' "$SCRIPT_DIR" "$(basename "$0")"
    exit 2
  fi
}

# Sets HW_ARCH (arm64|x86_64), HW_LABEL, ROSETTA (yes|no), BREW_NATIVE_PREFIX.
detect_arch() {
  if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
    HW_ARCH=arm64
    HW_LABEL="Apple silicon"
    BREW_NATIVE_PREFIX=/opt/homebrew
  else
    HW_ARCH=x86_64
    HW_LABEL="Intel"
    BREW_NATIVE_PREFIX=/usr/local
  fi
  if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
    ROSETTA=yes
  else
    ROSETTA=no
  fi
}

print_system() {
  detect_arch
  info "Hardware:  $HW_LABEL ($HW_ARCH), shell under Rosetta: $ROSETTA"
  info "macOS:     $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
  info "OpenSSL:   $("$OPENSSL" version) at $OPENSSL"
}

# Prints the subject line of every certificate in a PEM bundle.
# Fails (non-zero) if the bundle cannot be parsed.
bundle_subjects() {
  local out
  out="$("$OPENSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | "$OPENSSL" pkcs7 -print_certs -noout 2>/dev/null)" || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" | grep '^subject=' || return 1
}

# bundle_has_cn <file> <cn> -> 0 if a cert with that CN is in the bundle.
bundle_has_cn() {
  local subjects
  subjects="$(bundle_subjects "$1")" || return 2
  printf '%s\n' "$subjects" | grep -qF "$2"
}

# Number of certificates openssl can parse from a bundle.
bundle_count() {
  local subjects
  subjects="$(bundle_subjects "$1")" || { echo 0; return 1; }
  printf '%s\n' "$subjects" | grep -c '^subject='
}

# Prints "<FINGERPRINT> <certificate> (<issued by>)" for each entry in
# $BLOCKED_CERTS_FILE. Fails if the file is missing or any line is malformed.
load_blocked_certs() {
  [ -f "$BLOCKED_CERTS_FILE" ] || { err "Blocked certificate list not found: $BLOCKED_CERTS_FILE"; return 1; }
  awk -F ' [|] ' '
    /^[[:space:]]*(#|$)/ { next }
    NF != 3 || $1 !~ /^[0-9A-F]+$/ || length($1) != 64 {
      printf "[ERROR] %s:%d: malformed entry\n", FILENAME, NR > "/dev/stderr"; bad = 1; next
    }
    { printf "%s %s (%s)\n", $1, $2, $3; n++ }
    END { if (bad || n == 0) exit 1 }
  ' "$BLOCKED_CERTS_FILE"
}

# Apple's step 4 check, verbatim.
apple_check() {
  "$OPENSSL" crl2pkcs7 -nocrl -certfile "$CERT_FILE" | "$OPENSSL" pkcs7 -print_certs -noout \
    | grep -E 'emSign ECC Root CA - G3|AAA Certificate Services' || true
}

# Apple's step 2/3 filter, applied to an arbitrary input file.
# filter_out_header <header-line> <in> <out>
filter_out_header() {
  awk -v s="$1" '/^(===|###) /{skip=0} $0==s{skip=1} !skip' "$2" > "$3"
}

# Install <src> as $CERT_FILE (root:wheel 0644) via same-directory temp file + rename,
# so a failure at any point leaves the existing file untouched.
atomic_install() {
  local tmp="$CERT_FILE.tmp.$$"
  rm -f "$tmp"
  if ! install -m 0644 -o root -g wheel "$1" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$CERT_FILE"
}

# Apple step 1, plus handling for the article's "after a software update" note:
# if a macOS update put an untouched file back (both roots present) and it differs
# from the existing backup, archive the stale backup and back up the new file.
ensure_backup() {
  if [ ! -e "$BACKUP_FILE" ]; then
    cp -p "$CERT_FILE" "$BACKUP_FILE"
    ok "Step 1: backed up $CERT_FILE to $BACKUP_FILE"
    return
  fi
  if bundle_has_cn "$CERT_FILE" "$EMSIGN_CN" && bundle_has_cn "$CERT_FILE" "$AAA_CN" \
     && ! cmp -s "$CERT_FILE" "$BACKUP_FILE"; then
    local archived
    archived="$BACKUP_FILE.$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$BACKUP_FILE" "$archived"
    cp -p "$CERT_FILE" "$BACKUP_FILE"
    ok "Step 1: $CERT_FILE was replaced (likely by a macOS update); old backup archived to $archived, new backup at $BACKUP_FILE"
    return
  fi
  ok "Step 1: existing backup kept at $BACKUP_FILE"
}

# apply_fix <mode-label> <cn:header>... : Apple steps 1-4 for the given roots,
# with verification and automatic rollback if the result is not exactly as expected.
apply_fix() {
  local mode="$1"; shift
  require_macos
  require_root

  section "eMudhra cert.pem fix — $mode"
  print_system

  [ -e "$CERT_FILE" ] || die "$CERT_FILE does not exist."
  [ -L "$CERT_FILE" ] && die "$CERT_FILE is a symlink; refusing to modify it."
  [ -f "$CERT_FILE" ] || die "$CERT_FILE is not a regular file."

  local before
  before="$(bundle_count "$CERT_FILE")" || die "openssl cannot parse $CERT_FILE; restore with: sudo $SCRIPT_DIR/restore.sh"
  info "Certificates before: $before"

  # Work out which targets are still present and validate their header lines.
  local pair cn header todo="" n_todo=0
  for pair in "$@"; do
    cn="${pair%%|*}"; header="${pair#*|}"
    if bundle_has_cn "$CERT_FILE" "$cn"; then
      grep -qxF "$header" "$CERT_FILE" \
        || die "$cn is present but its header line is not in the expected format; refusing to edit. No changes made."
      todo="$todo$pair
"
      n_todo=$((n_todo + 1))
    else
      ok "Already absent: $cn"
    fi
  done

  if [ "$n_todo" -eq 0 ]; then
    section "Step 4: check"
    apple_check
    ok "Nothing to do; $CERT_FILE already has the target roots removed."
    return 0
  fi

  ensure_backup

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  cp -p "$CERT_FILE" "$WORK/snapshot.pem"
  cp "$CERT_FILE" "$WORK/current.pem"

  local step
  while IFS= read -r pair; do
    [ -n "$pair" ] || continue
    cn="${pair%%|*}"; header="${pair#*|}"
    step=2; [ "$cn" = "$AAA_CN" ] && step=3
    filter_out_header "$header" "$WORK/current.pem" "$WORK/next.pem"
    [ -s "$WORK/next.pem" ] || die "Filtered output for $cn is empty; no changes made."
    mv "$WORK/next.pem" "$WORK/current.pem"
    ok "Step $step: prepared removal of $cn"
  done <<EOF
$todo
EOF

  # Verify the candidate before installing it.
  local after
  after="$(bundle_count "$WORK/current.pem")" || die "Candidate file does not parse; no changes made."
  [ "$after" -eq $((before - n_todo)) ] \
    || die "Expected $((before - n_todo)) certificates after removal, got $after; no changes made."
  for pair in "$@"; do
    cn="${pair%%|*}"
    if bundle_has_cn "$WORK/current.pem" "$cn"; then
      die "$cn still present in candidate file; no changes made."
    fi
  done

  atomic_install "$WORK/current.pem" || die "Could not install new $CERT_FILE; the original is unchanged."

  # Post-install verification; roll back to the pre-run snapshot on any mismatch.
  local installed
  installed="$(bundle_count "$CERT_FILE")" || installed=0
  if ! cmp -s "$WORK/current.pem" "$CERT_FILE" || [ "$installed" != "$after" ]; then
    atomic_install "$WORK/snapshot.pem"
    die "Verification of installed file failed; restored the previous $CERT_FILE."
  fi
  ok "Installed $CERT_FILE (root:wheel 0644), certificates: $before -> $after"

  section "Step 4: check (Apple's command; lists any target root still present)"
  apple_check

  section "Done"
  ok "$mode applied."
  info "Tools using only $CERT_FILE may fail to verify some sites that chain to the removed root(s)."
  info "After every macOS update, re-run: $SCRIPT_DIR/assess.sh"
  info "To undo: sudo $SCRIPT_DIR/restore.sh"
}
