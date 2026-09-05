# Syncing Rule Sources

[Rule sources](../configuration/sources.md) can refresh themselves on a TTL while requests
are being served. That works, and it is the worse arrangement.

A cold or expired cache means a visitor waits on somebody else's HTTP server before their
page renders. Worse, a TTL expiring under load sends every concurrent request after the
same URL at once — a stampede against an upstream that is now, from its point of view,
being hammered by your site.

Moving the refresh out of band fixes both. This guide covers doing that.

## The shape of it

1. Refresh the caches at deploy time, and on a cron for anything that churns.
2. Put the runtime in offline mode so it reads those caches and never opens a socket.

## Refreshing

```bash
vendor/bin/firewall-sources config/firewall.yml
```

The command reads the same configuration your application does, collects every source
declared under any plugin's `metadata.sources`, and refreshes each one:

```
Cache directory: /var/cache/firewall/sources

  ✓ aws-ec2-us                  1284 entries in 412ms
  ✓ uptimerobot                 62 entries in 38ms
  ✓ tor-exits                   1533 entries in 190ms

3 sources refreshed.
```

Several config files can be passed, and are merged the same way the library merges them.

| Option | Effect |
|---|---|
| `--force` | Revalidate even when the cached copy is still fresh |
| `--dry-run` | Report what is cached and whether it is stale, without fetching |
| `--cache-dir=DIR` | Write somewhere other than the configured location |
| `--quiet` | Only report failures |

The same upstream declared on several plugin entries is fetched once per run, not once
per plugin — so pointing both a `challenge` and a `block` plugin at one list costs one
request.

## Failing a deploy on a bad list

Exit codes are meaningful:

| Code | Meaning |
|---|---|
| `0` | Every source loaded |
| `1` | At least one source failed |
| `2` | The configuration itself could not be read |

So a deploy step can simply not continue:

```bash
set -e
vendor/bin/firewall-sources config/firewall.yml
```

That is usually what you want for an allow list, where a source silently dropping out
narrows what is permitted and locks out the very automation that is running the deploy.
For sources you would rather degrade than block on, set `on_error: fail_open` in the
declaration and let the command's non-zero exit be your signal rather than your gate.

## Checking without fetching

`--dry-run` reports the state of each cache and touches no network:

```bash
vendor/bin/firewall-sources config/firewall.yml --dry-run
```

```
  aws-ec2-us                   https://example.org/v1/ranges.json (1284 entries, stale)
  uptimerobot                  /srv/app/lists/uptimerobot.txt (62 entries, fresh)
  tor-exits                    https://example.org/v1/tor.txt (not cached)
```

Useful in a health check, or when working out why a rule you expected is not applying.

## Going offline at runtime

Once something else is keeping the caches current, stop the request path from fetching:

```php
define('KANOPI_FIREWALL_SOURCES_OFFLINE', true);

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config/firewall.yml'])->evaluate();
```

In offline mode:

- A remote source is served from its cache, whatever its TTL says.
- A remote source with **nothing** cached raises an error rather than contributing an
  empty rule list. That failure is the point — an empty block list looks exactly like a
  working one until someone attacks you.
- Local files are still read normally. Syncing lists to disk and reading them from disk is
  the intended arrangement.

## Credentials

Sources behind authentication read their credentials from the configuration, and the
recommended shape puts the secret in the environment rather than the file:

```yaml
upstream:
  url: https://feeds.example.com/v1/list.json
  auth:
    type: bearer
    token: "%env(FEED_TOKEN)%"
```

Which means **the sync command needs those variables too**. It is a separate process from
your application, so a token exported by your web server's environment is not
automatically present in a cron job or a deploy script. A source that authenticates fine
in the request path and fails under cron is almost always this.

Nothing the command prints contains a credential — upstream URLs are redacted before they
reach stdout, stderr, or a log — so its output is safe to capture in CI.

## Cron

Match the interval to how fast the upstream actually moves, not to how often you would
like fresh data. A cloud provider's ranges change a few times a day; a curated list of
user agents changes when someone edits it.

```cron
# Refresh firewall lists every six hours
0 */6 * * * cd /srv/app && FEED_TOKEN=... vendor/bin/firewall-sources config/firewall.yml --quiet
```

Better still, source the same environment file your application uses rather than putting
secrets in the crontab, where they are readable by anyone who can list it.

`--quiet` reports only failures, so cron mails you when something breaks and stays silent
otherwise.

## A worked deploy step

```bash
#!/usr/bin/env bash
set -euo pipefail

composer install --no-dev --optimize-autoloader

# Refresh every declared list. A required source that cannot be read fails here,
# before any traffic reaches the new release.
vendor/bin/firewall-sources config/firewall.yml

# Confirm what landed.
vendor/bin/firewall-sources config/firewall.yml --dry-run
```

## Related

- [Rule Sources](../configuration/sources.md) — every source option, and the pipeline
- [Checking a Request](checking-requests.md) — asking whether a given request would be blocked
