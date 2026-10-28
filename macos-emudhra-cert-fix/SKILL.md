---
name: macos-emudhra-cert-fix
version: 1.2.0
argument-hint: "[assess | fix [mode 1|mode 2] | restore]"
description: Assess and fix the compromised eMudhra (emSign, sometimes spelled "mudhara") intermediate CA issue on macOS, per Apple support article 149555. Use when the user mentions eMudhra, emSign ECC Root CA - G3, AAA Certificate Services, the October 2026 CA compromise, /etc/ssl/cert.pem, or asks whether curl/git/python3/openssl on their Mac still trust the compromised certificates. Works on Intel and Apple silicon Macs.
---

# macOS eMudhra cert.pem fix

Source: <https://support.apple.com/en-us/149555> (published 2026-10-23).

## Background

The private keys of eight eMudhra intermediate CAs were compromised. Six of them issue TLS certificates, and each of those six has two certificates (12 in total):

- one issued by emSign Root TLS CA - G3, which chains to **emSign ECC Root CA - G3**
- one cross-signed by Sectigo, which chains to **AAA Certificate Services**

Apple blocks these automatically in Safari, Mail and apps that use Apple's networking and security frameworks. **Command-line tools** that read `/etc/ssl/cert.pem` (curl, git, python3, ruby, perl, openssl) don't apply that block until a future macOS update. Apple's workaround is to remove the root CA certificates from that file.

Intel and Apple silicon Macs use the same `/etc/ssl/cert.pem` and the same steps. The scripts detect the architecture (and whether the shell runs under Rosetta) and use it to find the native Homebrew CA bundles (`/usr/local` on Intel, `/opt/homebrew` on Apple silicon), which they report but don't modify.

## Scripts

All scripts are in `scripts/` next to this file. Each one is self-contained (it sources `_common.sh` from its own directory), uses absolute tool paths, sets `PATH` and `LC_ALL=C`, and runs on the stock macOS `/bin/bash` 3.2.

| Mode | Script | Root? | Apple steps |
|---|---|---|---|
| Assess | `assess.sh` | no | read-only check, plus step 4 |
| Fix mode 1 | `fix-mode1-emsign.sh` | yes | 1, 2, 4: remove emSign ECC Root CA - G3 |
| Fix mode 2 | `fix-mode2-emsign-aaa.sh` | yes | 1, 2, 3, 4: also remove AAA Certificate Services |
| Undo | `restore.sh` | yes | restore the step 1 backup |

The 12 blocked intermediate certificates (SHA-256 fingerprint, name, issuer) are listed in `data/blocked-certificates.txt`, one per line in the form `<fingerprint> | <certificate> | <issued by>`. `assess.sh` checks `/etc/ssl/cert.pem` against that list and stops with an error if the file is missing or any line is malformed. If Apple updates the list, edit only that file.

`assess.sh` exit codes: `0` both roots absent (mitigated), `10` emSign present (not mitigated), `11` only AAA present (mode 1 applied), `1` error.

The fix scripts:
- Back up the file to `/etc/ssl/cert.pem.orig`, keeping any existing backup (step 1). If a macOS update has replaced the file with an unmodified one, they archive the stale backup as `cert.pem.orig.<UTC timestamp>` instead of deleting it.
- Use Apple's exact `awk` filter and header lines.
- Refuse to edit if the file is a symlink, can't be parsed, or doesn't contain the expected header line.
- Build the new file in a temp directory and check it before installing it: it must parse, contain exactly N fewer certificates, and no longer contain the target roots. They then install it as `root:wheel 0644` and check it again, restoring the previous file automatically if anything doesn't match.
- Can safely be run again: if nothing is left to remove, they make no changes.

## Choosing what to do

The skill has two top-level options: **assess** and **fix**. Work out which one from the user's request or the skill arguments:

| User asked for | Do this |
|---|---|
| nothing specific (e.g. just invoked the skill) | Offer the two options, **assess** (read-only check) or **fix** (remove the roots), and wait for the answer. |
| `assess` / "check" / "am I affected?" | Workflow steps 1–2, then stop. Mention that **fix** is available if the result is 10 or 11. |
| `fix` with no mode | Run steps 1–2 first, so the choice is based on the current state, then offer **mode 1** and **mode 2** (step 3) and wait for the answer. |
| `fix mode 1` / `fix 1` / "emSign only" | Steps 1–2, then go straight to step 4 with `fix-mode1-emsign.sh`. |
| `fix mode 2` / `fix 2` / "both" / "all 12" | Steps 1–2, then go straight to step 4 with `fix-mode2-emsign-aaa.sh`. |
| `restore` / "undo" | Step 6. |

When offering choices, use the host's structured question tool if it has one (for example AskUserQuestion). Otherwise, ask in plain text. Don't pick an option for the user. If assess exits `0`, tell the user nothing needs fixing instead of offering fix modes. If it exits `11` and the user asked for **fix**, only mode 2 has anything left to do, so say that.

## Workflow

1. **Resolve the absolute scripts path.** It is this skill's base directory plus `/scripts`. Always give the user absolute paths, never `~` or relative ones.

2. **Assess.** Run `<abs>/scripts/assess.sh` yourself. It is read-only and doesn't need sudo. Summarize the result for the user: hardware, macOS version, which roots are present, backup status, any Homebrew bundles or `SSL_CERT_FILE`-style environment variables that bypass `/etc/ssl/cert.pem`, and the verdict.

3. **If exit code is 10 or 11, explain the two fix modes and let the user choose:**
   - **Mode 1** removes only emSign ECC Root CA - G3. It blocks the 6 intermediates issued under emSign. The 6 Sectigo cross-signed intermediates are still accepted, because they chain to AAA Certificate Services.
   - **Mode 2** also removes AAA Certificate Services, so all 12 are blocked. The trade-off: tools that use only `/etc/ssl/cert.pem` may fail to verify unaffected sites whose chains end at AAA Certificate Services. This mostly affects older Sectigo/Comodo chains.
   - Apple calls step 3 (AAA) optional. Both modes stop being needed once the macOS update that includes Apple's fix is installed.

4. **Ask the user to run exactly one command** in their own Terminal, for example:

   ```
   sudo /absolute/path/to/scripts/fix-mode1-emsign.sh
   ```

   Don't run `sudo` yourself, and don't give the user multi-line snippets or Apple's raw commands to paste. The script is the whole procedure.

5. **Verify.** When the user says it has finished, run `assess.sh` again yourself and confirm the exit code: `11` after mode 1, `0` after mode 2.

6. **Rollback** (if a tool breaks or the user asks): `sudo <abs>/scripts/restore.sh`.

7. **Aftercare.** Tell the user:
   - A macOS update can replace `/etc/ssl/cert.pem`. They should run `assess.sh` again after each update until the update containing Apple's fix is installed, and if a root has come back, run the same fix mode again. The script handles the backup refresh.
   - Apps that bundle their own CA lists (Homebrew `ca-certificates`/`openssl@3`, Python `certifi`, Node.js, Java, Firefox, and so on) aren't covered by this fix. They need updates from their own vendors.

## Exit codes of fix/restore scripts

`0` success or nothing to do. `1` failure: no change was made, or the previous file was restored. `2` not run as root; the script prints the exact `sudo` command to use.
