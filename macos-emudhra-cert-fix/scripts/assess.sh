#!/bin/bash
# ASSESS mode: read-only check of /etc/ssl/cert.pem against Apple article 149555.
# Makes no changes. Runs with or without sudo.
#
# Exit codes:
#   0  both emSign ECC Root CA - G3 and AAA Certificate Services are absent (fully mitigated)
#   10 emSign ECC Root CA - G3 is present (not mitigated)
#   11 emSign removed, AAA Certificate Services still present (fix mode 1 applied)
#   1  error (file missing or unparseable)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/_common.sh"

require_macos

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

section "System"
print_system
info "Running as: $(id -un) (uid $(id -u))"

section "$CERT_FILE"
[ -e "$CERT_FILE" ] || die "$CERT_FILE does not exist."
if [ -L "$CERT_FILE" ]; then
  warn "$CERT_FILE is a symlink to $(readlink "$CERT_FILE"); the fix scripts will refuse to modify it."
fi
info "Owner/mode: $(stat -f '%Su:%Sg %Lp' "$CERT_FILE"), size $(stat -f '%z' "$CERT_FILE") bytes"
info "SHA-256:    $(shasum -a 256 "$CERT_FILE" | awk '{print $1}')"
if ! COUNT="$(bundle_count "$CERT_FILE")"; then
  die "openssl cannot parse $CERT_FILE. Restore it with: sudo $SCRIPT_DIR/restore.sh"
fi
info "Certificates parsed: $COUNT"

EMSIGN_PRESENT=no
AAA_PRESENT=no
bundle_has_cn "$CERT_FILE" "$EMSIGN_CN" && EMSIGN_PRESENT=yes
bundle_has_cn "$CERT_FILE" "$AAA_CN" && AAA_PRESENT=yes

if [ "$EMSIGN_PRESENT" = yes ]; then warn "Present: $EMSIGN_CN"; else ok "Absent:  $EMSIGN_CN"; fi
if [ "$AAA_PRESENT" = yes ]; then warn "Present: $AAA_CN"; else ok "Absent:  $AAA_CN"; fi

# Sanity: the header lines the fix scripts key on must exist when the cert is present.
if [ "$EMSIGN_PRESENT" = yes ] && ! grep -qxF "$EMSIGN_HEADER" "$CERT_FILE"; then
  warn "emSign cert present but its header line has an unexpected format; fix scripts will refuse to edit."
fi
if [ "$AAA_PRESENT" = yes ] && ! grep -qxF "$AAA_HEADER" "$CERT_FILE"; then
  warn "AAA cert present but its header line has an unexpected format; fix scripts will refuse to edit."
fi

section "Blocked intermediate fingerprints in $CERT_FILE"
awk -v d="$TMPD" '
  /^-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/%04d.pem", d, n) }
  f { print > f }
  /^-----END CERTIFICATE-----/ { close(f); f = "" }
' "$CERT_FILE"
: > "$TMPD/fps"
for pem in "$TMPD"/*.pem; do
  [ -e "$pem" ] || continue
  "$OPENSSL" x509 -noout -fingerprint -sha256 -in "$pem" 2>/dev/null \
    | sed 's/^.*=//' | tr -d ':' | tr '[:lower:]' '[:upper:]' >> "$TMPD/fps"
done
BLOCKED="$(load_blocked_certs)" || die "Cannot read blocked certificate list $BLOCKED_CERTS_FILE."
N_BLOCKED="$(printf '%s\n' "$BLOCKED" | grep -c .)"
info "Checking $N_BLOCKED fingerprints from $BLOCKED_CERTS_FILE"
FOUND_BLOCKED=0
while IFS= read -r line; do
  fp="${line%% *}"
  if grep -qxF "$fp" "$TMPD/fps"; then
    warn "Blocked intermediate present: ${line#* }"
    FOUND_BLOCKED=$((FOUND_BLOCKED + 1))
  fi
done <<EOF
$BLOCKED
EOF
[ "$FOUND_BLOCKED" -eq 0 ] && ok "None of the $N_BLOCKED blocked intermediates are in the bundle (expected)."

section "Backup $BACKUP_FILE"
if [ -e "$BACKUP_FILE" ]; then
  info "Exists: $(stat -f '%Su:%Sg %Lp, %z bytes, modified %Sm' "$BACKUP_FILE")"
  if BCOUNT="$(bundle_count "$BACKUP_FILE")"; then
    info "Backup certificates parsed: $BCOUNT"
  else
    warn "Backup cannot be parsed by openssl."
  fi
  if cmp -s "$CERT_FILE" "$BACKUP_FILE"; then
    info "Backup is identical to the current file (no fix applied since backup)."
  fi
else
  info "No backup yet (created automatically by the fix scripts)."
fi

section "Other CA bundles (informational, not modified by this skill)"
# Intel Homebrew lives in /usr/local, Apple silicon Homebrew in /opt/homebrew.
# Both are checked because Rosetta setups can have both.
SEEN=""
for prefix in /opt/homebrew /usr/local; do
  label="non-native"
  [ "$prefix" = "$BREW_NATIVE_PREFIX" ] && label="native for $HW_LABEL"
  for rel in etc/ca-certificates/cert.pem etc/openssl@3/cert.pem etc/openssl@1.1/cert.pem etc/openssl/cert.pem; do
    f="$prefix/$rel"
    [ -e "$f" ] || continue
    id="$(stat -L -f '%d:%i' "$f")"
    case " $SEEN " in *" $id "*) continue ;; esac
    SEEN="$SEEN $id"
    hits=""
    bundle_has_cn "$f" "$EMSIGN_CN" && hits="$hits emSign"
    bundle_has_cn "$f" "$AAA_CN" && hits="$hits AAA"
    if [ -n "$hits" ]; then
      info "$f ($label Homebrew):$hits present. Update with 'brew upgrade ca-certificates' when Homebrew ships a fix."
    else
      info "$f ($label Homebrew): neither root present."
    fi
  done
done
[ -z "$SEEN" ] && info "No Homebrew CA bundles found."

for v in SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS; do
  eval "val=\${$v:-}"
  # shellcheck disable=SC2154
  [ -n "$val" ] && info "Env $v=$val (tools using it bypass $CERT_FILE)"
done
[ "$(id -u)" -eq 0 ] && info "Running under sudo: user environment variables were not inspected."

section "Apple step 4 check (lists any remaining target roots)"
apple_check

section "Verdict"
if [ "$EMSIGN_PRESENT" = yes ]; then
  warn "NOT MITIGATED: $CERT_FILE still trusts $EMSIGN_CN."
  printf '\nFix mode 1 (Apple steps 1, 2, 4: remove emSign only):\n  sudo %s/fix-mode1-emsign.sh\n' "$SCRIPT_DIR"
  printf 'Fix mode 2 (Apple steps 1-4: remove emSign and AAA Certificate Services):\n  sudo %s/fix-mode2-emsign-aaa.sh\n' "$SCRIPT_DIR"
  exit 10
elif [ "$AAA_PRESENT" = yes ]; then
  warn "PARTIAL: emSign removed, but the 6 Sectigo cross-signed intermediates still verify via $AAA_CN."
  printf '\nTo also remove AAA Certificate Services (fix mode 2):\n  sudo %s/fix-mode2-emsign-aaa.sh\n' "$SCRIPT_DIR"
  exit 11
else
  ok "MITIGATED: neither root is in $CERT_FILE."
  exit 0
fi
