# Presets

Presets are pre-configured firewall rule sets that ship with the library. Include one in your main configuration to block common attack patterns and malicious requests without writing rules yourself. They live in the package's [`presets/`](https://github.com/kanopi/firewall/tree/2.x/presets) directory, which `{presets_dir}` resolves to inside `vendor/`.

See [Available Presets](available.md) for what each one does, and [Using Presets](usage.md) for how to include, combine, and override them.

## Configuration Format

The firewall uses a canonical `plugins:` array format. Each entry in the array configures one plugin and supports the following keys:

- `plugin` — Fully-qualified plugin class name (string, double-quoted with escaped backslashes, e.g. `"Kanopi\\Firewall\\Plugins\\Url"`).
- `response` — One of:
  - `allow` — bypass / whitelist behavior.
  - `block` — deny / blacklist behavior.
  - `challenge` — serve a CAPTCHA-style interstitial; on success the visitor receives an HMAC-signed pass token (cookie + custom header) valid for `metadata.default_expiration_time` seconds. Requires a top-level `challenge:` section with a non-empty `secret`. See the main [README → Challenge Response Type](../plugins/challenges.md) for the full contract.
- `weight` — Integer execution order. Lower weights run first (e.g. `-200` before `-10` before `0`).
- `enable` — `true`/`false` toggle for the entry.
- `metadata` — Plugin-specific metadata (e.g. storage backends, GeoIP readers, external config file references).
- `config` — Plugin-specific rule list or scalar configuration.

Example skeleton:

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.100/32

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/blocked-path
```

### Preset composition and merging

When a preset is pulled in through `configs:`, the loader **appends** each included file's `plugins:` entries onto a single combined list — it does not class-key-merge entries. This means:

- Two files can each declare an entry for `Kanopi\Firewall\Plugins\Url` and both will be kept as separate entries with their own `response`, `weight`, `enable`, and `config`. They are not folded into one.
- Order of `configs:` includes does not collapse duplicates; instead, all entries land in the combined list and are then partitioned by `response` and sorted by `weight` at runtime.
- To override an entry from a preset, add another `plugins:` entry in your main config with a lower `weight` so it runs first, or disable an unwanted plugin upstream by republishing it with `enable: false`.

This is a meaningful behavior difference from the legacy `block:`/`bypass:` format (which keyed entries by class name and deep-merged). See [Legacy Config Format](../reference/legacy-format.md).

## Example Configurations

Three fully-commented example configs show complete, deployable setups. They are meant to be **copied into your project and edited**, not included via `configs:` — each one already declares its own storage and overrides.

| File | Shows |
|---|---|
| `example-usage.yml` | Composing multiple presets (`wordpress.yml` + `malicious-urls.yml`) with custom allow rules and additional plugins. |
| `example-malicious-requests-usage.yml` | Deploying `malicious-requests.yml` in production: storage, logging, and threshold overrides. |
| `example-rate-limiting-usage.yml` | Several rate limiting deployment scenarios side by side — Redis, database, and file storage, plus per-path limit overrides. |

```bash
cp presets/example-malicious-requests-usage.yml config/firewall.yml
# edit paths and credentials, then:
#   Firewall::create(['config/firewall.yml'])->evaluate();
```

Because each example is a menu of alternatives rather than one runnable config, read the comments before using one — several blocks are mutually exclusive and expect you to delete the ones you don't want.

## Security Recommendations

1. **Start Conservative**: Begin with `config.wordpress-simple.yml` before adding `malicious-urls.yml`
2. **Test Thoroughly**: Always test in staging before production
3. **Monitor Logs**: Watch for false positives in the first week
4. **Keep Updated**: Review and update presets as new threats emerge
5. **Layer Security**: Use these presets alongside other security measures (WAF, SSL, etc.)

## Performance Impact

- **Minimal**: URL pattern matching is very fast
- **Regex Rules**: Slightly slower than simple string matching, but still negligible
- **Rule Count**: Having 100+ rules has minimal performance impact
- **Plugin Weight**: URL plugin runs early (`weight: -100`) to block bad requests quickly
