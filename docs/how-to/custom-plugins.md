# Custom Plugin Implementation

Create a custom plugin to implement specific business logic:

```php
<?php

namespace App\Security\Firewall\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Symfony\Component\HttpFoundation\Request;

class ApiKeyValidator extends AbstractPluginBase
{
    private array $validApiKeys;
    
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        
        // Load API keys from configuration or database
        $this->validApiKeys = $metadata['api_keys'] ?? [];
    }
    
    protected function defaultName(): string
    {
        return 'API Key Validator';
    }
    
    public function getDescription(): string
    {
        return 'Validates API keys for authenticated endpoints';
    }
    
    public function evaluate(Request $request): bool
    {
        // Only check API endpoints
        if (!str_starts_with($request->getPathInfo(), '/api/')) {
            return false;
        }
        
        // Check for API key in header or query
        $apiKey = $request->headers->get('X-API-Key') 
                  ?? $request->query->get('api_key');
        
        if (!$apiKey) {
            $this->logger?->warning('Missing API key', [
                'ip' => $request->getClientIp(),
                'path' => $request->getPathInfo(),
            ]);
            return true; // Block request
        }
        
        if (!in_array($apiKey, $this->validApiKeys, true)) {
            $this->logger?->warning('Invalid API key', [
                'ip' => $request->getClientIp(),
                'api_key' => substr($apiKey, 0, 8) . '...',
            ]);
            return true; // Block request
        }
        
        return false; // Allow request
    }
    
    public function getStatusCode(): int
    {
        return 401; // Unauthorized
    }
}
```

Register the custom plugin in your configuration:

```yaml
plugins:
  - plugin: "App\\Security\\Firewall\\Plugins\\ApiKeyValidator"
    response: block
    weight: -150   # Run before rate limiting
    enable: true
    metadata:
      api_keys:
        - "sk_live_abcd1234567890"
        - "sk_live_efgh0987654321"
```

## Naming a custom plugin

`defaultName()` is what the plugin is called when the configuration declares no name of
its own. Override it, and `metadata.name` still overrides that:

```yaml
plugins:
  - plugin: "App\\Security\\Firewall\\Plugins\\ApiKeyValidator"
    response: block
    metadata:
      name: partner-api-keys
```

```
firewall.WARNING: Request blocked {"plugin_name":"partner-api-keys","plugin_type":"App\\Security\\Firewall\\Plugins\\ApiKeyValidator", …}
```

Override neither and the plugin logs its short class name — `ApiKeyValidator`.

> **Upgrading from `getName()`.** A plugin that implements `public function getName()`
> itself keeps working exactly as before; that is why `defaultName()` is a concrete method
> rather than an abstract one. Such a plugin simply never sees `metadata.name`, because it
> has taken over the method that reads it. Rename it to `protected function defaultName()`
> to opt in. See [`metadata.name`](../plugins/index.md#metadataname-naming-a-rule).
