# Configuration Overview

The firewall configuration consists of five main sections:

| Section     | Purpose                                                                    | Required |
|-------------|----------------------------------------------------------------------------|----------|
| `global`    | Defines global configuration settings                                      | No       |
| `storage`   | Defines where blocked IP addresses are persisted                           | Yes      |
| `plugins`   | Ordered list of plugin entries that allow (`response: allow`), challenge (`response: challenge`), or block (`response: block`) traffic | No       |
| `challenge` | Settings for the interstitial flow (provider, HMAC secret, cookie / header names). Required iff any plugin uses `response: challenge`. See [Challenge Response Type](../plugins/challenges.md). | Conditional |
| `logger`    | Monolog handlers for logging firewall events                               | No       |

Plugin rules do not have to live in the configuration file. See
[Rule Sources](sources.md) for pulling them from files, URLs, and third-party
lists in whatever format those are published in.

> **Legacy formats `bypass:` / `block:`** are still accepted and auto-normalized into `plugins:` entries at load time. See [Legacy Config Format](../reference/legacy-format.md). New configs should use the `plugins:` array.
