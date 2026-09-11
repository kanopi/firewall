# Security Policy

## Reporting a vulnerability

**Please do not open a public issue.** A public issue is indexed from the moment it is filed,
and every installation of this library stays exposed for as long as the fix takes.

Report it privately through GitHub:

**[Report a vulnerability →](https://github.com/kanopi/firewall/security/advisories/new)**

That opens a private advisory visible only to you and the maintainers. It needs no account
beyond the one you are reading this with, and no inbox on our side that could quietly stop
being read.

If that page is unavailable to you for any reason, open a
[Discussion](https://github.com/kanopi/firewall/discussions) asking a maintainer to contact
you — **without describing the vulnerability** — and we will take it from there.

### What to include

As much of this as you have. A partial report is worth sending; do not sit on one waiting to
complete it.

- What an attacker can do, and what they need in order to do it
- The affected version, and the PHP version
- A configuration that reproduces it, reduced as far as you can
- A request, or a short script, that demonstrates it

### What to expect

| | |
|---|---|
| Acknowledgement | Within **3 working days** |
| An assessment — whether we agree it is a vulnerability, and its severity | Within **10 working days** |
| Progress updates | At least every **10 working days** until it is resolved or closed |

If you have not heard from us inside the acknowledgement window, please chase us in a
Discussion without details. A missed reply is much more likely to be a failure of ours than
a judgement about your report.

## Supported versions

| Version | Security fixes |
|---|---|
| 2.x | Yes — and for **12 months** after 3.0.0 ships |
| 1.x | No |

The full policy, including bug-fix windows and PHP support, is in the
[Support Policy](https://kanopi.github.io/firewall/reference/support-policy/).

## Disclosure

We aim to release a fix before any public description of the issue.

- You will be credited by name or handle, unless you would rather not be.
- A [GitHub Security Advisory](https://github.com/kanopi/firewall/security/advisories) is
  published when the fix ships, which feeds the ecosystem's vulnerability databases so
  downstream sites are told to upgrade.
- If we cannot reproduce a report, or we conclude it is not a vulnerability, we will say so
  and explain why rather than letting it go quiet.

## What is in scope

This repository: the library, the shipped presets, and the `bin/` commands.

Worth stating plainly, because it is the most likely source of a mistaken report:

- **A rule that does not match something you expected is a false negative, not a
  vulnerability.** The presets are a starting point, not a guarantee. Open a normal issue.
- **A misconfiguration that weakens a deployment is a bug in the documentation at most.**
  If the documentation led you there, we want to know — as an issue.
- **A dependency's vulnerability belongs upstream**, though we would still like to hear
  about it so we can pin or patch.

A way to *bypass* a rule that is documented as blocking something is in scope, and is exactly
the kind of report we want.
