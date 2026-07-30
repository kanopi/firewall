# Checking a Request

`bin/firewall-check` answers one question from the terminal: **would this request be blocked, and by what?**

It runs the real evaluation path against a config you name, without needing a running site and without touching your production data.

```bash
vendor/bin/firewall-check --config=firewall.yml --ip=203.0.113.5 --url=/wp-admin/
```

```
BLOCKED  GET /wp-admin/
  client            203.0.113.5
  blocked by        IP Address
  status            400
  reason            blocked
  storage           throwaway (in-memory)
```

## Options

| Option | Purpose |
|---|---|
| `--config=FILE` | Config file. **Repeatable**, merged in order exactly as `Firewall::create()` merges them |
| `--ip=ADDRESS` | Client IP, IPv4 or IPv6. Default `127.0.0.1` |
| `--url=URL` | Path with optional query string. Default `/` |
| `--method=VERB` | HTTP method. Default `GET`, or `POST` when `--body` is given |
| `--header=NAME:VAL` | Request header. **Repeatable** |
| `--body=STRING` | Request body |
| `--explain` | Show every plugin that evaluated, plus the ones that never ran |
| `--json` | Machine-readable output |
| `--live-storage` | Use the configured storage instead of a throwaway — see [Safety](#safety) |

## Exit codes

Designed to compose in scripts and CI, so the verdict *is* the exit status:

| Code | Meaning |
|---|---|
| `0` | allowed |
| `1` | blocked |
| `2` | challenged |
| `64` | usage error |
| `70` | internal error |

```bash
if vendor/bin/firewall-check --config=firewall.yml --url=/wp-admin/ >/dev/null; then
  echo "Not blocked — the WordPress preset is not doing its job."
  exit 1
fi
```

## Understanding why

`--explain` lists every plugin that ran, with its result and timing, and then the plugins that never ran because something earlier matched. That second list is usually the answer to *"why wasn't this caught?"*:

```console
$ vendor/bin/firewall-check --config=firewall.yml --ip=203.0.113.5 --url=/wp-admin/ --explain

BLOCKED  GET /wp-admin/
  client            203.0.113.5
  blocked by        IP Address
  ...

Plugins evaluated, in order:
  MATCH   IP Address                     0.06 ms

Configured but not reached:
  block     Kanopi\Firewall\Plugins\Url              weight -10
  block     Kanopi\Firewall\Plugins\UserAgent        weight 0
```

The IP list matched first, so nothing else was consulted. If you were testing whether your URL rules catch `/wp-admin/`, this tells you the test never reached them.

The timings are real and occasionally revealing — `matomo/device-detector` is markedly more expensive on a cold call than the pattern-matching plugins.

## Safety

**Storage is replaced with a throwaway by default, and this matters.** A block is not a read-only event: it writes to storage, records an offense, and applies [`blocking_escalation`](../configuration/global.md#multiple-offenses-defense). A checker wired straight to a production config would **ban the address it was asked about**.

So by default the durable blocklist is *not* consulted and *not* written. The output says which mode you are in on the `storage` line.

`--live-storage` restores the configured backend when you genuinely need the repeat-offender state considered — for instance to confirm an address is currently banned rather than merely matching a rule. It prints a warning to stderr, and a blocked verdict **will** be recorded:

```bash
vendor/bin/firewall-check --config=firewall.yml --ip=203.0.113.5 --live-storage
```

If that records a block you did not want, clearing it means removing the entry from your [storage backend](../configuration/storage.md) directly — which is the reason the throwaway is the default.

## Scripting

`--json` writes a single object to stdout; warnings go to stderr, so the output stays parseable even with `--live-storage`.

```bash
vendor/bin/firewall-check --config=firewall.yml --ip=203.0.113.5 --json | jq -r .plugin
```

The tool redirects its own diagnostics to stderr so stdout carries nothing but the JSON document. One case is outside its control: PHP's CLI SAPI prints **startup** warnings to stdout before any script runs, so a duplicate `extension=` line in your `php.ini` would land ahead of the JSON and break the pipe. If you hit that, run it as:

```bash
php -d display_errors=stderr vendor/bin/firewall-check --config=firewall.yml --json
```

```json
{
    "verdict": "blocked",
    "plugin": "IP Address",
    "status": 400,
    "reason": "blocked",
    "request": { "ip": "203.0.113.5", "method": "GET", "path": "/", "query": null },
    "storage": "throwaway (in-memory)"
}
```

## Notes

- **Mode is forced to `exception`** regardless of what the config says. `Firewall::evaluate()` returns early in CLI under any other mode, which would report every request as allowed — so this is not optional, and it is why hand-rolled checking scripts so often appear to work while telling you nothing.
- **Plugins that reach the network still do so.** `AbuseIpdb` will consult its cache and, on a miss, call the API and spend quota. Nothing here suppresses that.
- **Attribution comes from the firewall's own decision log**, not from re-running each plugin — a second pass would repeat every side effect.
