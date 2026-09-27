<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Cache;

use Kanopi\Firewall\Cache\CachePoolException;
use Kanopi\Firewall\Cache\CachePoolFactory;
use Kanopi\Firewall\Cache\ReportingCacheBridge;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\RateLimitStorage\CacheRateLimitStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Cache pools built from a DSN, against a real Memcached and Redis (#394).
 *
 * The unit tests cover everything that does not need a server. This covers what does:
 * that a DSN really reaches the server and round-trips a value, that namespaces keep two
 * settings apart, that an object planted by another writer comes back as a miss rather
 * than as an instance, that an unreachable server fails fast, and that the user-agent
 * cache and rate limiting both work end to end on a DSN.
 *
 * CI runs both services. Locally, the ones that are not reachable skip.
 */
final class CachePoolDsnIntegrationTest extends IntegrationTestCase
{
    private string $namespace;

    protected function setUp(): void
    {
        parent::setUp();

        $this->namespace = 'fwtest' . bin2hex(random_bytes(4));
    }

    private function memcachedDsn(): string
    {
        $config = self::getMemcachedConfig();

        return sprintf('memcached://%s:%d', $config['host'], $config['port']);
    }

    private function redisDsn(): string
    {
        $config = self::getRedisConfig();

        return sprintf('redis://%s:%d', $config['host'], $config['port']);
    }

    private function requireMemcached(): void
    {
        $this->skipIfGroupDisabled('memcached');

        if (!extension_loaded('memcached')) {
            $this->markTestSkipped('ext-memcached is not installed.');
        }

        $config = self::getMemcachedConfig();
        $probe = new \Memcached();
        $probe->setOption(\Memcached::OPT_CONNECT_TIMEOUT, 500);
        $probe->addServer((string) $config['host'], (int) $config['port']);

        if ($probe->getVersion() === false) {
            $this->markTestSkipped('No Memcached server reachable with the configured settings.');
        }
    }

    private function requireRedis(): void
    {
        $this->skipIfGroupDisabled('redis');

        if (!extension_loaded('redis')) {
            $this->markTestSkipped('ext-redis is not installed.');
        }

        try {
            RedisAdapter::createConnection($this->redisDsn(), ['timeout' => 0.5]);
        } catch (\Throwable) {
            $this->markTestSkipped('No Redis server reachable with the configured settings.');
        }
    }

    private function roundTrips(CacheItemPoolInterface $pool): void
    {
        $item = $pool->getItem('verdict');
        $item->set(['country' => 'NZ', 'hits' => [1, 2, 3]]);

        $this->assertTrue($pool->save($item));
        $this->assertSame(['country' => 'NZ', 'hits' => [1, 2, 3]], $pool->getItem('verdict')->get());
    }

    // -----------------------------------------------------------------------
    // Memcached
    // -----------------------------------------------------------------------

    public function testAMemcachedDsnBuildsAWorkingPool(): void
    {
        $this->requireMemcached();

        $pool = CachePoolFactory::create(['adaptor' => $this->memcachedDsn(), 'namespace' => $this->namespace], 'unused');

        $this->assertInstanceOf(MemcachedAdapter::class, $pool);
        $this->roundTrips($pool);
        $pool->clear();
    }

    /**
     * Two settings on one server cannot read each other's keys.
     */
    public function testNamespacesKeepTwoSettingsApart(): void
    {
        $this->requireMemcached();

        $first = CachePoolFactory::create($this->memcachedDsn(), $this->namespace . 'a');
        $second = CachePoolFactory::create($this->memcachedDsn(), $this->namespace . 'b');
        $this->assertInstanceOf(CacheItemPoolInterface::class, $first);
        $this->assertInstanceOf(CacheItemPoolInterface::class, $second);

        $item = $first->getItem('shared-key');
        $item->set('first');
        $first->save($item);

        $this->assertFalse($second->getItem('shared-key')->isHit());
    }

    /**
     * Whatever else can write to the server does not get to choose a class for this
     * process to instantiate. Written with Symfony's own marshaller, which serialises
     * objects; read back through the pool the factory built, which refuses them.
     */
    public function testAnObjectPlantedByAnotherWriterIsAMiss(): void
    {
        $this->requireMemcached();

        $client = MemcachedAdapter::createConnection($this->memcachedDsn());
        $planter = new MemcachedAdapter($client, $this->namespace);
        $item = $planter->getItem('verdict');
        $item->set(new \ArrayObject(['gadget']));
        $this->assertTrue($planter->save($item));

        $pool = CachePoolFactory::create($this->memcachedDsn(), $this->namespace);
        $this->assertInstanceOf(CacheItemPoolInterface::class, $pool);

        $this->assertFalse($pool->getItem('verdict')->isHit());
        $planter->clear();
    }

    /**
     * An unreachable server is found when the pool is built, not on every lookup after.
     */
    public function testAnUnreachableMemcachedFailsFast(): void
    {
        $this->requireMemcached();

        $started = microtime(true);

        try {
            CachePoolFactory::create(['adaptor' => 'memcached://127.0.0.1:1', 'options' => ['connect_timeout' => 300]], 'ns');
            $this->fail('Expected a CachePoolException');
        } catch (CachePoolException $cachePoolException) {
            $this->assertFalse($cachePoolException->isNotAPool());
            $this->assertStringContainsString('no Memcached server answered', $cachePoolException->getMessage());
        }

        $this->assertLessThan(3.0, microtime(true) - $started, 'Bounded by the connect timeout');
    }

    /**
     * One of two servers down does not take the cache with it.
     *
     * The first operation on a key that hashes to the dead server fails -- that failure
     * is what ejects it -- and the retry lands on the live one. So a partial outage costs
     * at most one cache operation per request, which is why the write is tried twice
     * here rather than once. Which key hashes where depends on the random namespace, so
     * asserting a single write would pass or fail by chance.
     */
    public function testOneOfTwoServersDownStillBuildsAPool(): void
    {
        $this->requireMemcached();

        $config = self::getMemcachedConfig();
        $pool = CachePoolFactory::create([
            'adaptor' => sprintf('memcached:?host[127.0.0.1:1]&host[%s:%d]', $config['host'], $config['port']),
            'namespace' => $this->namespace,
            'options' => ['connect_timeout' => 300],
        ], 'unused');

        $this->assertInstanceOf(MemcachedAdapter::class, $pool);

        $item = $pool->getItem('verdict');
        $item->set('NZ');
        $this->assertTrue($pool->save($item) || $pool->save($item), 'Written on the first or, after ejection, the second attempt');
        $this->assertSame('NZ', $pool->getItem('verdict')->get());
        $pool->clear();
    }

    /**
     * The user-agent cache on Memcached: the corpus is written, and a second plugin --
     * a second request, in effect -- reads it back rather than writing it again.
     */
    public function testTheUserAgentCacheWarmsOnMemcachedAndIsReused(): void
    {
        $this->requireMemcached();

        $metadata = ['cache' => ['adaptor' => $this->memcachedDsn(), 'namespace' => $this->namespace]];
        $rules = ['bot:true', 'device.type:desktop'];
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'REMOTE_ADDR' => '66.249.66.1',
        ]);

        $before = $this->memcachedItemCount();
        (new UserAgent($metadata, $rules))->evaluate($request);
        $afterWarm = $this->memcachedItemCount();

        $this->assertGreaterThan($before, $afterWarm, 'The corpus was written to Memcached');

        $second = new UserAgent($metadata, $rules);
        $this->assertInstanceOf(ReportingCacheBridge::class, (new \ReflectionMethod($second, 'cache'))->invoke($second));
        $this->assertTrue($second->evaluate($request));
        $this->assertLessThanOrEqual($afterWarm + 1, $this->memcachedItemCount(), 'Read back, not written again');

        CachePoolFactory::create($this->memcachedDsn(), $this->namespace)?->clear();
    }

    private function memcachedItemCount(): int
    {
        $config = self::getMemcachedConfig();
        $client = new \Memcached();
        $client->addServer((string) $config['host'], (int) $config['port']);
        $stats = $client->getStats();

        return is_array($stats) ? (int) (current($stats)['curr_items'] ?? 0) : 0;
    }

    public function testRateLimitingCountsOnAMemcachedDsn(): void
    {
        $this->requireMemcached();

        $storage = new CacheRateLimitStorage(['adaptor' => $this->memcachedDsn(), 'namespace' => $this->namespace]);
        $now = time();

        $storage->recordRequest('203.0.113.5', $now);
        $storage->recordRequest('203.0.113.5', $now);

        $this->assertSame(2, $storage->countRequests('203.0.113.5', $now - 60, $now));
        CachePoolFactory::create($this->memcachedDsn(), $this->namespace)?->clear();
    }

    // -----------------------------------------------------------------------
    // Redis
    // -----------------------------------------------------------------------

    public function testARedisDsnBuildsAWorkingPool(): void
    {
        $this->requireRedis();

        $pool = CachePoolFactory::create(['adaptor' => $this->redisDsn(), 'namespace' => $this->namespace], 'unused');

        $this->assertInstanceOf(RedisAdapter::class, $pool);
        $this->roundTrips($pool);
        $pool->clear();
    }

    public function testAnUnreachableRedisFailsFast(): void
    {
        $this->requireRedis();

        $started = microtime(true);

        try {
            CachePoolFactory::create('redis://127.0.0.1:1', 'ns');
            $this->fail('Expected a CachePoolException');
        } catch (CachePoolException $cachePoolException) {
            $this->assertFalse($cachePoolException->isNotAPool());
            $this->assertStringContainsString('Redis connection failed', $cachePoolException->getMessage());
        }

        $this->assertLessThan(3.0, microtime(true) - $started, 'Bounded by the connect timeout');
    }

    public function testRateLimitingCountsOnARedisDsn(): void
    {
        $this->requireRedis();

        $storage = new CacheRateLimitStorage(['adaptor' => $this->redisDsn(), 'namespace' => $this->namespace]);
        $now = time();

        $storage->recordRequest('203.0.113.5', $now);

        $this->assertSame(1, $storage->countRequests('203.0.113.5', $now - 60, $now));
        CachePoolFactory::create($this->redisDsn(), $this->namespace)?->clear();
    }
}
