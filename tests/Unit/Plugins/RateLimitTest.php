<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\RateLimitStorage\PrunableRateLimitStorageInterface;
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
     * A storage that also records the `forget()` calls it receives.
     */
    protected function getPrunableMockStorage(int $count): RateLimitStorageInterface
    {
        return new class ($count) implements RateLimitStorageInterface, PrunableRateLimitStorageInterface {
            public array $recorded = [];

            public array $forgotten = [];

            public function __construct(private int $count)
            {
            }

            public function recordRequest(string $key, int $timestamp): void
            {
                $this->recorded[] = [$key, $timestamp];
            }

            public function countRequests(string $key, int $start, int $end): int
            {
                return $this->count;
            }

            public function forget(string $key, int $before): int
            {
                $this->forgotten[] = [$key, $before];

                return 0;
            }
        };
    }

    /**
     * An allowed request prunes this key's window before adding to it (#183).
     *
     * The cutoff must be the window start the count used, not something
     * looser: everything older has already stopped affecting the verdict, and
     * everything newer is still counted.
     */
    public function testAnAllowedRequestPrunesItsOwnWindow(): void
    {
        $request = Request::create('/test');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $storage = $this->getPrunableMockStorage(0);
        $plugin = $this->getRateLimit(
            ['default_rate' => 2, 'default_sample' => 30],
            [['path' => '/test', 'rate' => 2, 'sample' => 60]],
            $storage
        );

        $before = time();
        $this->assertFalse($plugin->evaluate($request));
        $after = time();

        $this->assertCount(1, $storage->forgotten);
        [$key, $cutoff] = $storage->forgotten[0];

        $this->assertSame($storage->recorded[0][0], $key, 'Pruned under the same key it recorded');
        $this->assertGreaterThanOrEqual($before - 60, $cutoff);
        $this->assertLessThanOrEqual($after - 60, $cutoff);
    }

    /**
     * A throttled request does no pruning.
     *
     * Records are only added on the allowed path, so pruning there is enough
     * to bound the growth -- a key over its limit stops being appended to and
     * stops growing on its own. Doing the work anyway would mean the firewall
     * spending more effort on traffic it is busy refusing.
     */
    public function testAThrottledRequestPrunesNothing(): void
    {
        $request = Request::create('/test');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $storage = $this->getPrunableMockStorage(3);
        $plugin = $this->getRateLimit(
            ['default_rate' => 5, 'default_sample' => 10],
            [['path' => '/test', 'rate' => 2, 'sample' => 60]],
            $storage
        );

        $this->assertTrue($plugin->evaluate($request));
        $this->assertSame([], $storage->forgotten);
        $this->assertSame([], $storage->recorded);
    }

    /**
     * A storage without the capability still works, and is not called.
     *
     * `plugins[].metadata.storage.type` accepts any implementor of
     * `RateLimitStorageInterface`, so a host's own backend that predates this
     * must keep working untouched.
     */
    public function testAStorageWithoutTheCapabilityIsUnaffected(): void
    {
        $request = Request::create('/test');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $storage = $this->getMockStorage(0);
        $plugin = $this->getRateLimit(
            ['default_rate' => 2, 'default_sample' => 30],
            [['path' => '/test', 'rate' => 2, 'sample' => 60]],
            $storage
        );

        $this->assertFalse($plugin->evaluate($request));
        $this->assertCount(1, $storage->recorded);
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
     * A default_rate of 0 must not refuse every request (#229).
     *
     * The check is `$count >= $rate`. With a rate of 0 that is `$count >= 0`,
     * which is true for the very first request from a client that has recorded
     * nothing -- so the value that reads as "unlimited" refused the whole site.
     */
    public function testZeroDefaultRateDoesNotBlockEveryRequest(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 0, 'default_sample' => 60],
            [],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * The same, for a client that has already been seen many times.
     *
     * Guards against a fix that only special-cases the first request.
     */
    public function testZeroDefaultRateDoesNotBlockAnEstablishedClient(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 0, 'default_sample' => 60],
            [],
            $this->getMockStorage(9_999)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * An unenforceable rule records nothing, so it costs no storage round trip.
     */
    public function testZeroRateRecordsNothing(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $mock = $this->getMockStorage(0);
        $plugin = $this->getRateLimit(
            ['default_rate' => 0, 'default_sample' => 60],
            [],
            $mock
        );

        $plugin->evaluate($request);

        $this->assertSame([], $mock->recorded);
    }

    /**
     * A per-rule rate of 0 is unenforceable for the same reason.
     */
    public function testZeroRuleRateDoesNotBlock(): void
    {
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 10, 'default_sample' => 10],
            [['path' => '/login', 'rate' => 0, 'sample' => 60]],
            $this->getMockStorage(50)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * A negative rate is unenforceable too -- `$count >= -1` is always true.
     */
    public function testNegativeRateDoesNotBlock(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => -1, 'default_sample' => 60],
            [],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * A rate of 1 is the smallest enforceable limit, and still enforces.
     *
     * The boundary matters: the fix must not turn 1 into "no limit" as well.
     */
    public function testRateOfOneStillEnforces(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 1, 'default_sample' => 60],
            [],
            $this->getMockStorage(1)
        );

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * A rate of 1 still allows a client that has recorded nothing yet.
     */
    public function testRateOfOneAllowsTheFirstRequest(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 1, 'default_sample' => 60],
            [],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * limit_unlisted_paths: false limits only what was listed (#226).
     */
    public function testUnlistedPathsAreNotLimitedWhenOptedOut(): void
    {
        $request = Request::create('/some/ordinary/page');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $mock = $this->getMockStorage(9_999);
        $plugin = $this->getRateLimit(
            ['default_rate' => 60, 'default_sample' => 60, 'limit_unlisted_paths' => false],
            [['path' => '/login', 'rate' => 5, 'sample' => 300]],
            $mock
        );

        $this->assertFalse($plugin->evaluate($request));
        $this->assertSame([], $mock->recorded, 'An unlimited path must not touch the counter store');
    }

    /**
     * Opting out must not stop the rules the operator did write.
     */
    public function testListedPathsAreStillLimitedWhenOptedOut(): void
    {
        $request = Request::create('/login');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 60, 'default_sample' => 60, 'limit_unlisted_paths' => false],
            [['path' => '/login', 'rate' => 5, 'sample' => 300]],
            $this->getMockStorage(5)
        );

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * default_rate stays the fallback for a listed rule with no rate of its own.
     *
     * The reason this is a separate key rather than overloading a rate of 0:
     * a value that switched the catch-all off would silently unlimit these too.
     */
    public function testDefaultRateStillAppliesToAListedRuleWhenOptedOut(): void
    {
        $request = Request::create('/api/thing');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 3, 'default_sample' => 60, 'limit_unlisted_paths' => false],
            [['path' => '/api/*']],
            $this->getMockStorage(3)
        );

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * Declaring nothing keeps the catch-all, which is what it has always done.
     */
    public function testUnlistedPathsAreLimitedByDefault(): void
    {
        $request = Request::create('/some/ordinary/page');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 60, 'default_sample' => 60],
            [['path' => '/login', 'rate' => 5, 'sample' => 300]],
            $this->getMockStorage(60)
        );

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * A rule the operator wrote with the pattern "*" is theirs, and is honoured.
     *
     * The opt-out keys off a marker on the synthesised rule rather than off the
     * pattern, precisely so this stays true.
     */
    public function testAnExplicitWildcardRuleIsHonouredWhenOptedOut(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 60, 'default_sample' => 60, 'limit_unlisted_paths' => false],
            [['path' => '*', 'rate' => 2, 'sample' => 60]],
            $this->getMockStorage(2)
        );

        $this->assertTrue($plugin->evaluate($request));
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


    /**
     * A rule entry that is not an array is skipped rather than inspected.
     *
     * A hand-written config can put a bare string in the rule list; reading
     * `['rate']` off it would be a fatal.
     */
    public function testANonArrayRuleEntryIsSkipped(): void
    {
        // Before the guard this was a fatal:
        // TypeError: Cannot access offset of type string on string

        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 10, 'default_sample' => 10],
            ['not-a-rule', ['path' => '/login', 'rate' => 5]],
            $this->getMockStorage(0)
        );

        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * A rule map with no `path` is skipped too, rather than matching everything.
     */
    public function testARuleWithoutAPathIsSkipped(): void
    {
        $request = Request::create('/anything');
        $request->server->set('REMOTE_ADDR', '203.0.113.5');

        $plugin = $this->getRateLimit(
            ['default_rate' => 10, 'default_sample' => 10],
            [['rate' => 1, 'sample' => 60]],
            $this->getMockStorage(50)
        );

        // Falls through to the catch-all at default_rate 10, not to the
        // path-less rule at 1.
        $this->assertTrue($plugin->evaluate($request));
    }
}
