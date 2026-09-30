# Platform Integration

Each snippet below uses the default `mode: block`, where the firewall sends its own response and exits. If you set `mode: exception`, wrap `evaluate()` as shown in [Error Handling & Exceptions](../reference/error-handling.md).

## Drupal

Add to `settings.php` before the container configuration:

```php
// Load composer autoloader if not already loaded
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}

// Initialize firewall
if (class_exists('\Kanopi\Firewall\Firewall')) {
    $firewall_config = __DIR__ . '/firewall.yml';
    if (file_exists($firewall_config)) {
        \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
    }
}
```

Drupal's routes all go through `index.php`, so the default `path_source` is right for them. `settings.php` is also loaded by the files Drupal serves directly (`core/install.php`, `core/rebuild.php`, `core/authorize.php`). A rule on those paths, like the ones in `presets/drupal.yml`, only fires with `path_source: script_name`. See [Path Source](../configuration/global.md#path-source).

## WordPress

Add to `wp-config.php` after `ABSPATH` is defined but before `wp-settings.php`:

```php
// Firewall integration
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
    
    if (class_exists('\Kanopi\Firewall\Firewall')) {
        $firewall_config = __DIR__ . '/firewall/config.yml';
        if (file_exists($firewall_config)) {
            \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
        }
    }
}
```

**Set `path_source: script_name` in that config.** WordPress serves `wp-login.php`, `xmlrpc.php`, `wp-cron.php` and every `/wp-admin/*.php` as files of their own. Under the default `path_source`, the firewall matches each of them as `/`, so `presets/wordpress.yml` and any `/wp-login.php` rate limit never fire on them:

```yaml
global:
  path_source: script_name
  # base_path: /blog       # if WordPress is installed in a subdirectory
```

See [Path Source](../configuration/global.md#path-source).

## Symfony

Add to `public/index.php` before the kernel boot:

```php
use App\Kernel;
use Kanopi\Firewall\Firewall;

require_once dirname(__DIR__).'/vendor/autoload_runtime.php';

return function (array $context) {
    // Initialize firewall
    if (class_exists(Firewall::class)) {
        $configPath = dirname(__DIR__) . '/config/firewall.yml';
        if (file_exists($configPath)) {
            Firewall::create([$configPath])->evaluate();
        }
    }
    
    return new Kernel($context['APP_ENV'], (bool) $context['APP_DEBUG']);
};
```

Every request goes through `index.php`, so keep the default `path_source`. See [Path Source](../configuration/global.md#path-source).

## Laravel

Add to `public/index.php` after the autoloader:

```php
require __DIR__.'/../vendor/autoload.php';

// Firewall integration
if (class_exists('\Kanopi\Firewall\Firewall')) {
    $firewall_config = __DIR__ . '/../config/firewall.yml';
    if (file_exists($firewall_config)) {
        \Kanopi\Firewall\Firewall::create([$firewall_config])->evaluate();
    }
}

$app = require_once __DIR__.'/../bootstrap/app.php';
```

Every request goes through `index.php`, so keep the default `path_source`. See [Path Source](../configuration/global.md#path-source).
