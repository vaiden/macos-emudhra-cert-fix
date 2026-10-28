# macOS eMudhra cert fix

In October 2026, the private keys of several eMudhra certificate authorities were compromised. Apple blocks the affected certificates in Safari, Mail and most apps. Command-line tools like `curl`, `git` and `python3` don't get that protection yet, because they trust whatever is in `/etc/ssl/cert.pem`.

This repo is an agent skill (it also works fine without an agent) that checks your Mac and applies [Apple's recommended fix](https://support.apple.com/en-us/149555) safely. It works on both Intel and Apple silicon Macs.

## Install with skills.sh (recommended)

```bash
npx skills add vaiden/macos-emudhra-cert-fix
```

The CLI asks which agents to install it for. Add `-g` to make it available in all your projects. To install it straight into Claude Code everywhere:

```bash
npx skills add vaiden/macos-emudhra-cert-fix -g -a claude-code
```

## Or link it into Claude Code by hand

From a clone of this repo:

```bash
ln -s "$PWD/macos-emudhra-cert-fix" ~/.claude/skills/macos-emudhra-cert-fix
```

## Use it with your agent

Start a new session and type `/macos-emudhra-cert-fix`. It asks whether you want to **assess** or **fix**, and walks you through the rest. The agent never runs `sudo` itself. When something needs root, it gives you one command to run.

## Use it by hand

Check your Mac first:

```bash
./macos-emudhra-cert-fix/scripts/assess.sh
```

If it reports a problem, pick one of the two fixes:

- **Mode 1** removes the emSign root. This blocks 6 of the 12 certificates.
- **Mode 2** also removes AAA Certificate Services, which blocks all 12. A few older sites might stop verifying in command-line tools that rely only on this file.

```bash
sudo "$PWD/macos-emudhra-cert-fix/scripts/fix-mode2-emsign-aaa.sh"
```

Changed your mind? `sudo .../restore.sh` brings the original back.

## Good to know

- Your original file is backed up to `/etc/ssl/cert.pem.orig` before anything changes.
- Every change is verified, and rolled back automatically if something looks off.
- Running a fix twice is harmless.
- macOS updates can restore the original file. Run `assess.sh` again after updating until Apple ships its own fix.
- Apps that bundle their own certificates (Python `certifi`, Node, Java, Firefox) aren't covered. Update those separately.

## What's inside

```
macos-emudhra-cert-fix/
├── SKILL.md                         instructions for the agent
├── data/blocked-certificates.txt    the 12 blocked certificates (from Apple)
└── scripts/
    ├── assess.sh                    read-only check, no sudo needed
    ├── fix-mode1-emsign.sh          removes emSign ECC Root CA - G3
    ├── fix-mode2-emsign-aaa.sh      also removes AAA Certificate Services
    └── restore.sh                   puts the original file back
```

## License

[MIT](LICENSE)
