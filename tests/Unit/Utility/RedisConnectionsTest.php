<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\RedisConnections;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;

/**
 * The per-process Redis connection registry (#263).
 *
 * `ext-redis` connects lazily when options are passed to the constructor, so these
 * construct real `Redis` objects without needing a server. What is under test is which
 * object comes back, not whether it can talk to anything.
 */
#[RequiresPhpExtension('redis')]
class RedisConnectionsTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        RedisConnections::reset();
    }

    protected function tearDown(): void
    {
        RedisConnections::reset();
        parent::tearDown();
    }

    /**
     * The same target is opened once.
     *
     * This is the whole point: the block list and the rate limiter pointed at one
     * server should share a connection rather than opening two per request.
     */
    public function testTheSameTargetIsShared(): void
    {
        $options = ['host' => '127.0.0.1', 'port' => 6379, 'connectTimeout' => 0.001];

        $this->assertSame(
            RedisConnections::get($options),
            RedisConnections::get($options),
            'Two backends on one server should share a connection'
        );
    }

    /**
     * A connection is given a bounded timeout even when the config names none.
     *
     * `new Redis($options)` connects during construction, and with no timeout
     * among the options `ext-redis` falls back to `default_socket_timeout` --
     * 60 seconds on a stock PHP. A host that silently drops packets, which is
     * what a firewalled or wrong-subnet Redis looks like, therefore hung the
     * request for a minute (#273).
     *
     * Asserted through identity rather than by reading the option back: the
     * defaults are applied before the key is taken, so a bare config and one
     * naming the same values are the same target.
     */
    public function testATimeoutIsAppliedWhenNoneIsConfigured(): void
    {
        $this->assertSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379]),
            RedisConnections::get([
                'host' => '127.0.0.1',
                'port' => 6379,
                'connectTimeout' => 1.5,
                'readTimeout' => 1.5,
            ]),
            'A bare config should already carry the default timeouts'
        );
    }

    /**
     * A configured timeout is not overwritten by the default.
     *
     * A deployment reaching a Redis over a link slow enough to need longer must
     * be able to say so, and gets its own connection for saying it.
     */
    public function testAConfiguredTimeoutWins(): void
    {
        $this->assertNotSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379]),
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'connectTimeout' => 5]),
            'An explicit timeout is a different target, not the default'
        );
    }

    /**
     * Option order is not part of the target's identity.
     */
    public function testOptionOrderDoesNotMatter(): void
    {
        $this->assertSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'connectTimeout' => 0.001]),
            RedisConnections::get(['connectTimeout' => 0.001, 'port' => 6379, 'host' => '127.0.0.1']),
        );
    }

    /**
     * A different server gets its own connection.
     */
    public function testADifferentHostIsNotShared(): void
    {
        $this->assertNotSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'connectTimeout' => 0.001]),
            RedisConnections::get(['host' => '127.0.0.2', 'port' => 6379, 'connectTimeout' => 0.001]),
        );
    }

    /**
     * So does a different database on the same server.
     *
     * Sharing these would have one backend's keys land in the other's database.
     */
    public function testADifferentDatabaseIsNotShared(): void
    {
        $this->assertNotSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'database' => 0, 'connectTimeout' => 0.001]),
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'database' => 1, 'connectTimeout' => 0.001]),
        );
    }

    /**
     * Different credentials are different targets.
     */
    public function testDifferentCredentialsAreNotShared(): void
    {
        $this->assertNotSame(
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'auth' => 'one', 'connectTimeout' => 0.001]),
            RedisConnections::get(['host' => '127.0.0.1', 'port' => 6379, 'auth' => 'two', 'connectTimeout' => 0.001]),
        );
    }

    /**
     * An object among the options does not take part in identifying the target.
     *
     * Tested against the key directly rather than through get(): passing an option
     * ext-redis does not recognise makes its constructor warn, which would put a
     * warning in the suite to prove something about hashing.
     */
    public function testAnObjectOptionIsIgnoredForIdentity(): void
    {
        $key = new \ReflectionMethod(RedisConnections::class, 'key');
        $key->setAccessible(true);

        $base = ['host' => '127.0.0.1', 'port' => 6379];

        $this->assertSame(
            $key->invoke(null, $base),
            $key->invoke(null, $base + ['handler' => new \stdClass()]),
            'Object state must not reach the key'
        );
    }

    /**
     * reset() forgets them, so one test's server cannot answer for another's.
     */
    public function testResetForgetsConnections(): void
    {
        $options = ['host' => '127.0.0.1', 'port' => 6379, 'connectTimeout' => 0.001];
        $first = RedisConnections::get($options);

        RedisConnections::reset();

        $this->assertNotSame($first, RedisConnections::get($options));
    }
}
