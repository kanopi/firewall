# Legacy Configuration Format

Earlier versions of this library configured plugins in two separate top-level sections (`bypass:` and `block:`), each keyed by the plugin class name. This format is still accepted — `Kanopi\Firewall\Utility\PluginConfigNormalizer` rewrites it into the `plugins:` array shape at load time — but it will be removed in a future major release. New configs should use the `plugins:` array described above.

**Side-by-side**

| Legacy (deprecated)                             | New (`plugins:` array)               |
|-------------------------------------------------|--------------------------------------|
| `bypass:` section                               | entry with `response: allow`         |
| `block:` section                                | entry with `response: block`         |
| keyed by plugin class                           | `plugin: "..."` field on each entry  |
| `priority:`                                     | `weight:`                            |
| one instance per class per section              | multiple instances per class allowed |
| deep-merges by class across `configs:` includes | appends entries across includes      |

**Same config in both shapes**

```yaml
# Legacy (deprecated)
bypass:
  "Kanopi\\Firewall\\Plugins\\IpAddress":
    priority: -200
    enable: true
    config:
      - 192.168.1.0/24

block:
  "Kanopi\\Firewall\\Plugins\\Url":
    priority: -10
    enable: true
    config:
      - path:/wp-admin
```

```yaml
# New (canonical)
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 192.168.1.0/24

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/wp-admin
```

You can also mix both formats in the same config during migration — legacy entries are normalized first, then appended to whatever is already in `plugins:`.

## Preset-style example

Older configurations used top-level `bypass:` and `block:` sections keyed by plugin class. That shape is still accepted, but it is normalized at load time by `Kanopi\Firewall\Utility\PluginConfigNormalizer` into the canonical `plugins:` array, and **it will be removed in a future major version**. New configs should use the `plugins:` array directly.

Mini side-by-side:

Legacy (deprecated):

```yaml
bypass:
  Kanopi\Firewall\Plugins\IpAddress:
    priority: -200
    enable: true
    config:
      - 203.0.113.100

block:
  Kanopi\Firewall\Plugins\Url:
    priority: -10
    enable: true
    config:
      - path:/foo
```

Canonical (new):

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\IpAddress"
    response: allow
    weight: -200
    enable: true
    config:
      - 203.0.113.100

  - plugin: "Kanopi\\Firewall\\Plugins\\Url"
    response: block
    weight: -10
    enable: true
    config:
      - path:/foo
```

Mapping:

- `bypass:` → `response: allow`
- `block:` → `response: block`
- `priority:` → `weight:`
- Class-keyed map → flat list of entries with `plugin:` set to the (double-quoted, escaped) class name

Note that the legacy format keyed entries by class name, so a class could appear at most once per file. The canonical format allows multiple entries for the same plugin class, and entries from preset includes are appended (not class-merged) into a single combined list.
## Rate-limit example

Earlier releases configured plugins via top-level `bypass:` and `block:` sections keyed by class name. That format is still accepted but is auto-normalized at load time by `Kanopi\Firewall\Utility\PluginConfigNormalizer` into the canonical `plugins:` array, and **it will be removed in a future major version**. New configs should use the `plugins:` array.

Mini side-by-side for the RateLimit plugin:

Legacy (deprecated):

```yaml
block:
  Kanopi\Firewall\Plugins\RateLimit:
    priority: 0
    enable: true
    config:
      - path: /login
        rate: 5
        sample: 300
```

Canonical (new):

```yaml
plugins:
  - plugin: "Kanopi\\Firewall\\Plugins\\RateLimit"
    response: block
    weight: 0
    enable: true
    config:
      - path: /login
        rate: 5
        sample: 300
```

Mapping: `bypass:` → `response: allow`, `block:` → `response: block`, `priority:` → `weight:`, and the class-keyed map becomes a flat list of entries with `plugin:` set to the (double-quoted, backslash-escaped) class name.
