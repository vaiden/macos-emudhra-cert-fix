#!/bin/bash
# FIX MODE 2 (Apple article 149555, steps 1, 2, 3, 4):
# remove emSign ECC Root CA - G3 and AAA Certificate Services from /etc/ssl/cert.pem.
# Blocks all 12 compromised intermediate certificates for tools that use this file.
#
# Usage: sudo <absolute_path>/fix-mode2-emsign-aaa.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/_common.sh"

apply_fix "Fix mode 2 (remove emSign ECC Root CA - G3 and AAA Certificate Services)" \
  "$EMSIGN_CN|$EMSIGN_HEADER" \
  "$AAA_CN|$AAA_HEADER"
