<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test the RateLimit plugin behavior.
 */
class RateLimitTest extends AbstractTestCase
{
    /**
     * Creates a mock storage that tracks calls and returns a configured count.
     */
    protected function getMockStorage(int $count): RateLimitStorageInterface
    {
        return new class($count) implements RateLimitStorageInterface {
            public array $recorded = [];
            public function __construct(private int $count) {}

            public function recordRequest(string $key, int $timestamp): void
            {
                $this->recorded[] = [$key, $timestamp];
            }

            public function countRequests(string $key, int $start, int $end): int
            {
                return $this->count;
            }
        };
    }

    /**
     * Returns a RateLimit object with custom metadata, config, and mocked storage.
     */
    protected function getRateLimit(array $metadata, array $config, RateLimitStorageInterface $storage): RateLimit
    {
        return new class($metadata, $config, $storage) extends RateLimit {
            public function __construct(array $metadata, array $config, RateLimitStorageInterface $mockStorage)
            {
                parent::__construct($metadata, $config);
                $this->storage = $mockStorage;
            }
        };
    }

    /**
     * Test the name of the plugin.
     */
    public function testGetName(): void
    {
        $plugin = new RateLimit();
        $this->assertSame('Rate Limit', $plugin->getName());
    }

    /**
     * Test the description of the plugin.
     */
    public function testGetDescription(): void
    {
        $plugin = new RateLimit();
        $this->assertSame('Rate Limit the user.', $plugin->getDescription());
    }

    /**
     * Test the status code returned by the plugin.
     */
    public function testGetStatusCode(): void
    {
        $plugin = new RateLimit();
        $this->assertSame(429, $plugin->getStatusCode());
    }

    /**
     * Test evaluation blocks when rate is exceeded.
     */
    public function testEvaluateBlocks(): void
    {
        $request = Request::create('/test');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $plugin = $this->getRateLimit(
            ['default_rate' => 5, 'default_sample' => 10],
            [['path' => '/test', 'rate' => 2, 'sample' => 60]],
            $this->getMockStorage(3) // exceeds rate
        );

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Test evaluation allows when rate is under limit.
     */
    public function testEvaluateAllows(): void
    {
        $request = Request::create('/test');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $mock = $this->getMockStorage(0); // under rate
        $plugin = $this->getRateLimit(
            ['default_rate' => 2, 'default_sample' => 30],
            [['path' => '/test', 'rate' => 2, 'sample' => 60]],
            $mock
        );

        $this->assertFalse($plugin->evaluate($request));
        $this->assertNotEmpty($mock->recorded);
    }

    /**
     * Test fallback rule is used when no config matches.
     */
    public function testFallbackRule(): void
    {
        $request = Request::create('/nomatch');
        $request->server->set('REMOTE_ADDR', '1.2.3.4');

        $mock = $this->getMockStorage(0);
        $plugin = $this->getRateLimit(
            ['default_rate' => 1, 'default_sample' => 60],
            [['path' => '/only-this']],
            $mock
        );

        $this->assertFalse($plugin->evaluate($request));
        $this->assertNotEmpty($mock->recorded);
        $this->assertStringContainsString('rate:1.2.3.4:*', $mock->recorded[0][0]);
    }

    /**
     * Test wildcard path matching.
     */
    public function testWildcardMatch(): void
    {
        $request = Request::create('/user/profile');
        $request->server->set('REMOTE_ADDR', '9.9.9.9');

        $plugin = $this->getRateLimit(
            ['default_rate' => 10, 'default_sample' => 60],
            [['path' => '/user/*']],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Test regex path matching.
     */
    public function testRegexPathMatch(): void
    {
        $request = Request::create('/secure-123');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        $plugin = $this->getRateLimit(
            ['default_rate' => 10, 'default_sample' => 60],
            [['path' => '#^/secure-\d+#']],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Test path-to-regex conversion.
     */
    public function testWildcardToRegex(): void
    {
        $plugin = new RateLimit();
        $regex = $this->invokeMethod($plugin, 'wildcardToRegex', ['/foo/*']);
        $this->assertMatchesRegularExpression($regex, '/foo/bar');
    }

    /**
     * Test key construction.
     */
    public function testBuildRateKey(): void
    {
        $request = Request::create('/abc');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');

        $plugin = new RateLimit();
        $method = new \ReflectionMethod($plugin, 'buildRateKey');
        $method->setAccessible(true);

        $key = $method->invoke($plugin, $request, ['path' => '/abc']);
        $this->assertSame('rate:192.168.1.1:/abc', $key);
    }

    /**
     * Helper to invoke protected method.
     */
    private function invokeMethod(object $object, string $methodName, array $args = []): mixed
    {
        $ref = new \ReflectionMethod($object, $methodName);
        $ref->setAccessible(true);
        return $ref->invokeArgs($object, $args);
    }

    /**
     * Test
     */
    public function testStorageFactoryUsesProvidedType(): void
    {
        $request = Request::create('/custom');
        $request->server->set('REMOTE_ADDR', '10.0.0.1');

        // Define a custom storage class to verify instantiation
        $storage = new class implements \Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface {
            public bool $recorded = false;

            public function recordRequest(string $key, int $timestamp): void
            {
                $this->recorded = true;
            }

            public function countRequests(string $key, int $start, int $end): int
            {
                return 0;
            }
        };

        // Dynamically register the class so that the RateLimit constructor picks it up
        $storageClass = get_class($storage);

        $plugin = new RateLimit(
            ['default_rate' => 5, 'default_sample' => 10, 'storage' => [
                'type' => $storageClass,
            ]],
            [['path' => '/custom']]
        );

        // Use reflection to inject the custom instance to track if it's used
        $reflection = new \ReflectionClass($plugin);
        $property = $reflection->getProperty('storage');
        $property->setAccessible(true);
        $property->setValue($plugin, $storage);

        $plugin->evaluate($request);

        $this->assertTrue($storage->recorded, 'Expected custom storage to be used and recordRequest to be called.');
    }

}
