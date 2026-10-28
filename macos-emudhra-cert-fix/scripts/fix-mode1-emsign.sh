#!/bin/bash
# FIX MODE 1 (Apple article 149555, steps 1, 2, 4):
# remove emSign ECC Root CA - G3 from /etc/ssl/cert.pem.
# Blocks the 6 intermediates issued under emSign Root TLS CA - G3. The 6 Sectigo
# cross-signed intermediates still verify via AAA Certificate Services (see mode 2).
#
# Usage: sudo <absolute_path>/fix-mode1-emsign.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/_common.sh"

apply_fix "Fix mode 1 (remove emSign ECC Root CA - G3)" \
  "$EMSIGN_CN|$EMSIGN_HEADER"
