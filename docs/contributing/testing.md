# Testing

**All new features must have 100% test coverage.**

## Writing Tests

1. **Unit Tests**: Required for all new code
   - Test individual methods and classes in isolation
   - Mock dependencies when appropriate
   - Place in `tests/Unit/` directory

2. **Integration Tests**: Required when:
   - Testing interaction between multiple components
   - Testing database or file system operations
   - Testing the full request/response cycle
   - Place in `tests/Integration/` directory

## Test Structure Example

```php
<?php

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use PHPUnit\Framework\TestCase;
use Kanopi\Firewall\Plugins\YourPlugin;

class YourPluginTest extends TestCase
{
    /**
     * Tests that the plugin correctly identifies blocked patterns.
     */
    public function testBlocksMaliciousPattern(): void
    {
        // Arrange
        $plugin = new YourPlugin([], ['pattern' => 'malicious']);
        
        // Act
        $result = $plugin->evaluate($this->createRequest('malicious-content'));
        
        // Assert
        $this->assertTrue($result);
    }
}
```

## Running Tests

The firewall includes a comprehensive test suite. Run tests with:

```bash
# Run all tests
composer test

# Run with coverage
composer test:coverage

# Run specific test suite
./vendor/bin/phpunit tests/Unit/Plugins/

# Run integration tests
./vendor/bin/phpunit tests/Integration/
```

## Static Analysis and Code Style

```bash
composer check          # phpcs + phpstan (level max) + rector --dry-run
composer check:code     # PHP_CodeSniffer against phpcs_ruleset.xml
composer check:security # PHPStan at level max
composer check:rector   # Rector, dry run

composer fix            # php -l + phpcbf + rector, applied
```

## Testing Against Another PHP Version

`bin/test.sh` runs the quality gates inside a throwaway Docker container, which is how you reproduce a CI failure on a PHP version you don't have locally:

```bash
# Defaults to cimg/php:8.2
bash bin/test.sh

# Pick a version, or a different base image
PHP_VERSION=8.3 bash bin/test.sh
PHP_IMAGE=php PHP_VERSION=8.1-cli bash bin/test.sh
```

It copies the working tree into the container, discards `composer.lock` and `vendor/` so dependencies resolve fresh for that PHP version, then runs `check:code`, `check:security`, and `check:rector`. The container is removed afterwards. Note that it does **not** run PHPUnit — use `composer test` locally for that.

## Performance Benchmarks

The repository ships a load-testing harness that measures throughput, latency, memory, and false-positive rate under mixed legitimate/malicious traffic. See [tests/Performance/README.md](https://github.com/kanopi/firewall/blob/2.x/tests/Performance/README.md).

```bash
bash tests/Performance/run-local-test.sh
```

## Example Test Case

```php
<?php

use PHPUnit\Framework\TestCase;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

class FirewallTest extends TestCase
{
    public function testBlocksMaliciousIp(): void
    {
        $config = [
            'storage' => [
                'type' => 'Kanopi\Firewall\Storage\InMemoryStorage'
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\IpAddress',
                    'response' => 'block',
                    'enable' => true,
                    'config' => ['192.168.1.100'],
                ],
            ],
        ];
        
        $firewall = Firewall::create([$config]);
        
        // Create a request from the blocked IP
        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.168.1.100'
        ]);
        
        // The firewall should block this request
        $this->expectException(\Exception::class);
        $firewall->evaluate($request);
    }
}
```
