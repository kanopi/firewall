# Dynamic Configuration Overrides

For dynamic environments (Docker, multi-site installations), you can override YAML configuration with PHP arrays. Override paths target the **source YAML shape** (before plugin normalization runs), so the right path depends on how your YAML is written.

**Overriding entries written in the `plugins:` array** — the path includes the list index (`0`, `1`, `2`, …) in declaration order:

```php
<?php
$overrides = [
    // Override storage location
    '[storage][config][file]' => $_ENV['FIREWALL_STORAGE_PATH'] ?? '/tmp/firewall.data',

    // Override GeoIP database path on the 2nd plugin entry (index 1)
    '[plugins][1][metadata][reader][db]' => $_ENV['GEOIP_DB_PATH'],

    // Override Redis connection on the 4th plugin entry (index 3)
    '[plugins][3][metadata][storage][config][redis][host]' => $_ENV['REDIS_HOST'] ?? 'localhost',

    // Disable a plugin entry
    '[plugins][2][enable]' => false,
];

\Kanopi\Firewall\Firewall::create([__DIR__ . '/config.yml'], $overrides)->evaluate();
```

**Overriding entries written in the legacy `block:` / `bypass:` format** — paths still address the plugin by class name (legacy format is normalized after overrides are merged, so this continues to work):

```php
<?php
$overrides = [
    '[block][\Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]' => $_ENV['GEOIP_DB_PATH'],
    '[block][\Kanopi\Firewall\Plugins\UserAgent][enable]' => false,
];
```

**Sections you have not declared are created for you.** An override writes into `global:`, `storage:`, `logger:`, `bypass:` or `block:` even when your YAML leaves that section out entirely — you do not have to add a placeholder entry first.

**An override that cannot be applied is silently ignored.** This happens when the path has to traverse *through* a value that is not an array:

```yaml
storage: /tmp/firewall.data   # a scalar, not a mapping
```

```php
// Dropped — `[storage]` is a string, so there is no `[config]` to write into.
// No exception, no log entry, and the original scalar is left intact.
'[storage][config][file]' => '/tmp/other.data',
```

Because there is no signal when this happens, assert the value landed if the override matters:

```php
$config = \Kanopi\Firewall\Utility\Config::load([$configPath], $overrides);
if (($config['storage']['config']['file'] ?? null) !== $expectedPath) {
    throw new \RuntimeException('Firewall storage override did not apply.');
}
```
