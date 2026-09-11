# Support Policy

What is supported, for how long, and what can change under you on an upgrade.

## Versioning

[Semantic Versioning](https://semver.org/).

| Release | Carries | Example |
|---|---|---|
| **Patch** (2.25.**1**) | Fixes. No new configuration keys, and no changed meaning for a value that already works | A backend that mishandled a value it was given |
| **Minor** (2.**26**.0) | New features and new configuration keys. Existing configuration keeps working and keeps meaning the same thing | A new plugin; a new `global:` setting that defaults to today's behaviour |
| **Major** (**3**.0.0) | Changes that need you to do something | The single-pass evaluation change |

A new setting that changes behaviour by default is a **major**, not a minor. That is why
`global.stale_source_error_after` shipped switched off in 2.25.0: on by default, it would
have failed a deploy that passed the day before.

## PHP versions

2.x supports **PHP 8.1 through 8.5**, and every release is tested against all five.

`composer.lock` is not committed, so each PHP version resolves its own dependency set — 8.1
resolves Symfony 6.4 and DBAL 4.2, 8.2 and above resolve Symfony 8.1. Both are supported
configurations, not accidents.

## Presets can change what they block

Presets ship **inside the package**. `composer update` within a minor line can therefore
change what gets blocked on your site with no change to your configuration.

Two things make that visible:

- Each rule set carries `# Preset-Version: N`, and
  [`presets/CHANGELOG.md`](https://github.com/kanopi/firewall/blob/2.x/presets/CHANGELOG.md)
  records what changed about what it matches.
- Release notes call out preset behaviour changes under **What changes on upgrade**, beside
  the code changes.

If you would rather they never moved, copy the preset into your own configuration and
include your copy. [Custom Presets](../presets/custom.md) covers that.

## The 2.x line, once 3.0 ships

| | |
|---|---|
| Security fixes | **12 months** from the 3.0.0 release |
| Bug fixes | **6 months** from the 3.0.0 release |
| New features | None. 2.x is feature-complete when 3.0 ships |
| PHP support | Unchanged for the life of the line: 8.1–8.5 |

Documentation for 2.x stays published and reachable after 3.0 — the version selector keeps
it, rather than the site silently becoming 3.x documentation for everyone.

### Why this is written down at all

Cautious adopters ask before they install, and "we will see" is a reason not to. It also
makes the case for batching breaking changes into 3.0 easier to make: a supported 2.x with a
stated end is a much smaller ask than an unsupported one with none.

## Reporting a security issue

There is no `SECURITY.md` and no private disclosure route yet, which is
[being fixed](https://github.com/kanopi/firewall/issues/320). Until it is, please **do not
open a public issue** for an unfixed vulnerability — reach the maintainers through
[Discussions](https://github.com/kanopi/firewall/discussions) instead.

Once that lands, 2.x receives security fixes for the window stated above.
