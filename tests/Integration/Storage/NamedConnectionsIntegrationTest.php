<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Kanopi\Firewall\Cache\CachePoolFactory;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\MemcachedStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Kanopi\Firewall\Utility\Connections;
use Kanopi\Firewall\Utility\DegradedBackends;
use Monolog\Handler\RedisHandler;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;
use Symfony\Component\Cache\Adapter\RedisAdapter;

/**
 * Named connections against a real Memcached and Redis (#395).
 *
 * What the unit tests cannot show without a server: that one Memcached client really is
 * shared between the block list and a cache, that a Monolog handler taking a Redis client
 * -- the case that had no YAML at all -- writes through a named connection, and that a
 * named Redis that is down leaves the firewall starting, with the backend that uses it
 * degraded rather than pointed at a default server.
 */
final class NamedConnectionsIntegrationTest extends IntegrationTestCase
{
    private string $prefix;

    protected function setUp(): void
    {
        parent::setUp();

        DegradedBackends::reset();
        $this->prefix = 'fwtest:' . bin2hex(random_bytes(6)) . ':';
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
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

        if ((new Connections(['m' => $this->memcachedDsn()]))->probe('m') !== null) {
            $this->markTestSkipped('No Memcached server reachable with the configured settings.');
        }
    }

    private function requireRedis(): void
    {
        $this->skipIfGroupDisabled('redis');

        if (!extension_loaded('redis')) {
            $this->markTestSkipped('ext-redis is not installed.');
        }

        if ((new Connections(['r' => $this->redisDsn()]))->probe('r') !== null) {
            $this->markTestSkipped('No Redis server reachable with the configured settings.');
        }

        DegradedBackends::reset();
    }

    /**
     * One client, handed to the block list and to a cache.
     */
    public function testOneMemcachedClientIsSharedByStorageAndACache(): void
    {
        $this->requireMemcached();

        $resolved = Connections::resolveIn([
            'connections' => ['cache' => $this->memcachedDsn()],
            'storage' => ['config' => ['instance' => '%connection(cache)%', 'memcached' => ['prefix' => $this->prefix]]],
            'cache' => ['adaptor' => '%connection(cache)%', 'namespace' => 'fwtest' . bin2hex(random_bytes(3))],
        ]);

        $client = $resolved['storage']['config']['instance'];
        $this->assertInstanceOf(\Memcached::class, $client);
        $this->assertSame($client, $resolved['cache']['adaptor']);

        $storage = new MemcachedStorage($resolved['storage']['config']);
        $storage->set('203.0.113.5', ['reason' => 'shared'], 60);
        $this->assertSame(['reason' => 'shared'], $storage->get('203.0.113.5'));

        $pool = CachePoolFactory::create($resolved['cache'], 'unused');
        $this->assertInstanceOf(MemcachedAdapter::class, $pool);
        $item = $pool->getItem('verdict');
        $item->set(true);
        $this->assertTrue($pool->save($item));

        $storage->reset();
        $pool->clear();
    }

    public function testANamedRedisClientBacksTheBlockListAndACache(): void
    {
        $this->requireRedis();

        $resolved = Connections::resolveIn([
            'connections' => ['redis' => ['dsn' => $this->redisDsn(), 'timeout' => 2]],
            'storage' => ['config' => ['instance' => '%connection(redis)%', 'redis' => ['prefix' => $this->prefix]]],
            'cache' => '%connection(redis)%',
        ]);

        $this->assertInstanceOf(\Redis::class, $resolved['storage']['config']['instance']);

        $storage = new RedisStorage($resolved['storage']['config']);
        $storage->set('203.0.113.5', ['reason' => 'named'], 60);
        $this->assertSame(['reason' => 'named'], $storage->get('203.0.113.5'));
        $this->assertInstanceOf(RedisAdapter::class, CachePoolFactory::create(['adaptor' => $resolved['cache']], 'fwtest'));

        $storage->reset();
    }

    /**
     * The case that had no YAML at all: a handler whose constructor takes a client.
     */
    public function testAMonologHandlerTakingARedisClientWritesThroughIt(): void
    {
        $this->requireRedis();

        $key = $this->prefix . 'log';

        Firewall::create([[
            'connections' => ['redis' => $this->redisDsn()],
            'logger' => [['class' => RedisHandler::class, 'args' => ['%connection(redis)%', $key]]],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'global' => ['mode' => 'exception'],
        ]]);

        $this->assertInstanceOf(RedisHandler::class, LoggingFactory::logger()->getHandlers()[0] ?? null);

        LoggingFactory::logger()->warning('named connection probe');

        $client = (new Connections(['r' => $this->redisDsn()]))->get('r');
        $this->assertInstanceOf(\Redis::class, $client);
        $entries = $client->lRange($key, 0, -1);
        $client->del($key);

        $this->assertIsArray($entries);
        $this->assertStringContainsString('named connection probe', implode("\n", $entries));
    }

    /**
     * A named Redis that is down does not stop the firewall starting (#356). The backend
     * that uses it degrades and says so -- it is not quietly pointed at localhost.
     */
    public function testAnUnreachableNamedRedisDegradesRatherThanFailing(): void
    {
        $this->requireRedis();

        $firewall = Firewall::create([[
            'connections' => ['redis' => ['dsn' => 'redis://127.0.0.1:1', 'timeout' => 0.3]],
            'storage' => ['type' => RedisStorage::class, 'config' => ['instance' => '%connection(redis)%']],
            'global' => ['mode' => 'exception'],
        ]]);

        $components = array_column($firewall->getDegradedBackends(), 'component');
        $this->assertContains('named connection', $components);
        $this->assertContains('block list', $components);
    }

    /**
     * A Memcached DSN that cannot even be parsed is degraded the same way, and the probe
     * says so.
     */
    public function testAMalformedNamedMemcachedDegrades(): void
    {
        $this->requireMemcached();

        $connections = new Connections(['cache' => 'memcached://']);

        $this->assertNull($connections->get('cache'));
        $this->assertSame('named connection', DegradedBackends::all()[0]['component'] ?? null);
        $this->assertStringContainsString('could not be built', (string) $connections->probe('cache'));
    }

    public function testTheProbeAnswersForEachKind(): void
    {
        $this->requireMemcached();
        $this->requireRedis();

        $connections = new Connections([
            'memcached' => $this->memcachedDsn(),
            'redis' => $this->redisDsn(),
            'memcached-down' => ['dsn' => 'memcached://127.0.0.1:1', 'connect_timeout' => 300],
        ]);

        $this->assertNull($connections->probe('memcached'));
        $this->assertNull($connections->probe('redis'));
        $this->assertNotNull($connections->probe('memcached-down'));
    }
}
