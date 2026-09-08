<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use GeoIp2\Database\Reader;
use GeoIp2\Model\Asn as AsnModel;
use Kanopi\Firewall\Plugins\Asn;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit tests for the ASN plugin.
 */
class AsnTest extends AbstractTestCase
{
    /**
     * Returns a testable Asn plugin with a mocked GeoIP2 reader.
     */
    private function createPluginWithMockReader(?Reader $mockReader = null): Asn
    {
        if ($mockReader === null) {
            $model = new AsnModel([
                'autonomous_system_number' => 12345,
                'autonomous_system_organization' => 'MockOrg',
                'ip_address' => '127.0.0.1',
                'prefix_len' => 24,
            ]);

            $mockReader = $this->createMock(Reader::class);
            $mockReader->method('asn')->willReturn($model);
        }

        return new class(['reader' => ['type' => 'mock', 'instance' => $mockReader]]) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'] ?? null;
            }
        };
    }

    /**
     * The same harness, with rules that read two different variables.
     */
    private function createPluginWithRules(Reader $mockReader): Asn
    {
        return new class(
            ['reader' => ['type' => 'mock', 'instance' => $mockReader]],
            ['asn:99999', 'asn_org:NotThisOrg']
        ) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'] ?? null;
            }
        };
    }

    /** Tests the plugin name string. */
    public function testGetName(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $this->assertSame('Autonomous System Network', $plugin->getName());
    }

    /** Tests the plugin description string. */
    public function testGetDescription(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $this->assertSame('Evaluate the GeoLocation Details', $plugin->getDescription());
    }

    /**
     * Tests evaluate() returns false (allow) when no reader was ever
     * configured — the plugin is a no-op for opt-out users.
     */
    public function testEvaluateAllowsWhenReaderNotConfigured(): void
    {
        $plugin = new class() extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertFalse($plugin->evaluate($request));
    }

    /**
     * Security regression: when the operator configured a reader but
     * initialization failed, the plugin must fail closed (return true =
     * block) by default. Pre-fix this returned false (allow), which
     * silently disabled the block list on every transient init failure.
     */
    public function testEvaluateFailsClosedWhenConfiguredReaderInitFails(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertTrue(
            $plugin->evaluate($request),
            'Configured-but-broken reader must fail closed (block) by default'
        );
    }

    /**
     * Operators that prefer availability over enforcement can opt back in
     * to the pre-fix behaviour via metadata.fail_open = true. This is a
     * deliberate, documented escape hatch — not the default.
     */
    public function testEvaluateRespectsExplicitFailOpenOptIn(): void
    {
        $plugin = new class([
            'reader' => ['type' => 'mock', 'instance' => null],
            'fail_open' => true,
        ]) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertFalse(
            $plugin->evaluate($request),
            'metadata.fail_open=true must restore pre-fix allow-on-failure semantics'
        );
    }

    /** Tests getRequestValue returns false if the reader is null. */
    public function testGetRequestValueReturnsFalseIfReaderIsNull(): void
    {
        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => null]]) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '1.1.1.1']);
        $this->assertFalse($method->invoke($plugin, $request, 'asn'));
    }

    /** Tests getRequestValue returns null when reader throws exception. */
    public function testGetRequestValueReturnsNullOnException(): void
    {
        $reader = $this->createMock(Reader::class);
        $reader->method('asn')->willThrowException(new \RuntimeException("Simulated failure"));

        $plugin = $this->createPluginWithMockReader($reader);
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '9.9.9.9']);
        $this->assertNull($method->invoke($plugin, $request, 'asn'));
    }

    /** Tests getRequestValue returns ASN and ASN Org from valid reader. */
    public function testGetRequestValueExtractsAsnData(): void
    {
        $asnModel = new AsnModel([
            'autonomous_system_number' => 15169,
            'autonomous_system_organization' => 'Google LLC',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->method('asn')->willReturn($asnModel);

        $plugin = $this->createPluginWithMockReader($reader);
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '127.0.0.1']);
        $this->assertSame(15169, $method->invoke($plugin, $request, 'asn'));
        $this->assertSame('Google LLC', $method->invoke($plugin, $request, 'asn_org'));
    }

    /** Tests getRequestValue returns null for unsupported variable keys. */
    public function testGetRequestValueReturnsNullForUnsupportedKeys(): void
    {
        $plugin = $this->createPluginWithMockReader();
        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '3.3.3.3']);
        $this->assertNull($method->invoke($plugin, $request, 'unsupported_key'));
    }

    /**
     * Tests that evaluateRequest() is called from evaluate().
     * We override evaluateRequest() and return true, while using a mock Reader.
     */
    public function testEvaluateUsesEvaluateRequest(): void
    {
        $reader = $this->createMock(\GeoIp2\Database\Reader::class);
        $reader->method('asn')->willReturn(new \GeoIp2\Model\Asn([
            'autonomous_system_number' => 1,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]));

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends Asn {
            public bool $wasCalled = false;

            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }

            public function evaluateRequest(Request $request, array $config = []): bool {
                $this->wasCalled = true;
                return true;
            }
        };

        $request = new Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertTrue($plugin->evaluate($request));
        $this->assertTrue($plugin->wasCalled, 'evaluateRequest() should be called');
    }

    /**
     * Tests getRequestValue returns false if reader does not have the asn() method.
     * This uses GeoIp2\WebService\Client which lacks an asn() method by design.
     */
    public function testGetRequestValueReturnsFalseIfMethodMissing(): void
    {
        $reader = $this->createMock(\GeoIp2\WebService\Client::class); // ✅ client has no `asn()`

        $plugin = new class(['reader' => ['type' => 'mock', 'instance' => $reader]]) extends \Kanopi\Firewall\Plugins\Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'];
            }
        };

        $ref = new \ReflectionClass($plugin);
        $method = $ref->getMethod('getRequestValue');
        $method->setAccessible(true);

        $request = new \Symfony\Component\HttpFoundation\Request([], [], [], [], [], ['REMOTE_ADDR' => '8.8.8.8']);
        $this->assertFalse($method->invoke($plugin, $request, 'asn'), 'Should return false when asn method is missing');
    }

    /**
     * The database is read once per address per request, not once per variable (#6).
     *
     * getValue() is called once for each rule variable, and each call used to do
     * its own read -- so `asn` and `asn_org` in one rule set read the same record
     * twice. The record for one address cannot change within a request, so the
     * second read could never return anything different.
     */
    public function testTheDatabaseIsReadOncePerAddress(): void
    {
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        // The assertion: exactly one read, across both variables.
        $reader->expects($this->once())->method('asn')->willReturn($model);

        $plugin = $this->createPluginWithRules($reader);

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '127.0.0.1');

        $plugin->evaluate($request);
    }

    /**
     * Two different addresses still get their own read.
     */
    public function testADifferentAddressIsReadSeparately(): void
    {
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '127.0.0.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->expects($this->exactly(2))->method('asn')->willReturn($model);

        $plugin = $this->createPluginWithRules($reader);

        foreach (['198.51.100.1', '203.0.113.9'] as $ip) {
            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', $ip);
            $plugin->evaluate($request);
        }
    }

    /**
     * A reader that is not a reader looks nothing up, and does not blow up.
     */
    public function testNoReaderYieldsNoRecord(): void
    {
        $plugin = new class(
            ['reader' => ['type' => 'mock', 'instance' => null]],
            ['asn:99999']
        ) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return null;
            }
        };

        $request = Request::create('/');
        $request->server->set('REMOTE_ADDR', '198.51.100.1');

        // Fails closed on a configured-but-unusable reader, and does not fatal.
        $this->assertTrue($plugin->evaluate($request));
    }


    /**
     * With a pool configured, a second request for the same address reads no
     * database at all (#6).
     */
    public function testAResolvedValueIsCachedAcrossRequests(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '198.51.100.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->expects($this->once())->method('asn')->willReturn($model);

        foreach ([1, 2] as $ignored) {
            // A fresh plugin each time, because a plugin is constructed per
            // request. Reusing one instance would prove nothing: the
            // per-request memo would answer the second call on its own.
            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', '198.51.100.1');
            $this->cachingPlugin($reader, $pool)->evaluate($request);
        }
    }

    /**
     * A different address is looked up separately.
     */
    public function testTheCacheIsKeyedOnTheAddress(): void
    {
        $pool = new \Symfony\Component\Cache\Adapter\ArrayAdapter();
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '198.51.100.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->expects($this->exactly(2))->method('asn')->willReturn($model);

        foreach (['198.51.100.1', '203.0.113.9'] as $ip) {
            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', $ip);
            $this->cachingPlugin($reader, $pool)->evaluate($request);
        }
    }

    /**
     * Caching is off unless asked for.
     *
     * Measured, a cache is a net loss below roughly a 26% hit rate -- a miss
     * costs the database read plus a write. Defaulting it on would make the
     * attack case worse.
     */
    public function testCachingIsOffByDefault(): void
    {
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '198.51.100.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->expects($this->exactly(2))->method('asn')->willReturn($model);

        foreach ([1, 2] as $ignored) {
            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', '198.51.100.1');
            $this->createPluginWithRules($reader)->evaluate($request);
        }
    }

    /**
     * A pool that cannot be built leaves the rule working, just uncached.
     */
    public function testAnUnusableCacheAdaptorStillResolves(): void
    {
        $model = new AsnModel([
            'autonomous_system_number' => 12345,
            'autonomous_system_organization' => 'MockOrg',
            'ip_address' => '198.51.100.1',
            'prefix_len' => 24,
        ]);

        $reader = $this->createMock(Reader::class);
        $reader->method('asn')->willReturn($model);

        foreach ([['adaptor' => 'NoSuchAdaptorClass'], ['adaptor' => \stdClass::class], []] as $cacheConfig) {
            $plugin = $this->cachingPlugin($reader, $cacheConfig);

            $request = Request::create('/');
            $request->server->set('REMOTE_ADDR', '198.51.100.1');

            $this->assertIsBool($plugin->evaluate($request));
        }
    }

    /**
     * The harness, with a cache configured.
     *
     * @param mixed $cache
     *   A pool instance, or a `metadata.cache` array.
     */
    private function cachingPlugin(Reader $mockReader, mixed $cache): Asn
    {
        return new class(
            [
                'reader' => ['type' => 'mock', 'instance' => $mockReader],
                'cache' => $cache,
            ],
            ['asn:99999', 'asn_org:NotThisOrg']
        ) extends Asn {
            protected function createService(?string $type, array $config = []): \GeoIp2\Database\Reader|\GeoIp2\WebService\Client|null {
                return $config['instance'] ?? null;
            }
        };
    }
}
