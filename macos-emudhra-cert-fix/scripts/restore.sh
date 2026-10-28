#!/bin/bash
# RESTORE: put /etc/ssl/cert.pem back from /etc/ssl/cert.pem.orig (Apple's step 1 backup).
# The backup itself is kept.
#
# Usage: sudo <absolute_path>/restore.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/_common.sh"

require_macos
require_root

section "Restore $CERT_FILE"
[ -f "$BACKUP_FILE" ] || die "No backup at $BACKUP_FILE; nothing to restore."
count="$(bundle_count "$BACKUP_FILE")" || die "Backup $BACKUP_FILE does not parse; refusing to restore it."
[ -L "$CERT_FILE" ] && die "$CERT_FILE is a symlink; refusing to modify it."

if [ -e "$CERT_FILE" ] && cmp -s "$BACKUP_FILE" "$CERT_FILE"; then
  ok "$CERT_FILE already matches the backup; nothing to do."
  exit 0
fi

atomic_install "$BACKUP_FILE" || die "Could not install backup; $CERT_FILE is unchanged."
cmp -s "$BACKUP_FILE" "$CERT_FILE" || die "Restored file does not match backup."
ok "Restored $CERT_FILE from $BACKUP_FILE ($count certificates)."

section "Step 4: check"
apple_check
