<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Redis configured where it cannot be used (#356).
 *
 * The library degrades for every other unreachable backend and fataled for
 * this one. `RedisStorage` caught `\Exception`, which covers a server that is
 * not answering — but `ext-redis` not being installed throws `\Error` from
 * `new Redis()`, and that was caught by nothing: not here, and not by a host
 * catching `\Exception` or `FirewallException` either. The firewall did not
 * start at all.
 *
 * These tests run on a host **without** the extension, which is where the bug
 * lives and where CI's other jobs do not go — the phpunit matrix has a Redis
 * service, so the covered paths there are the ones that work. They skip where
 * the extension is present, which is honest: the assertion is about its
 * absence.
 */
final class RedisWithoutExtensionTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (extension_loaded('redis')) {
            $this->markTestSkipped('This asserts what happens without ext-redis, and it is loaded here.');
        }

        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * The firewall starts, and keeps evaluating.
     *
     * The whole bug in one assertion: on `mode: block` a firewall that does
     * not start is not a firewall running without a block list, it is no
     * protection at all.
     */
    public function testTheFirewallStartsWithoutTheExtension(): void
    {
        $firewall = Firewall::create([[
            'storage' => [
                'type' => RedisStorage::class,
                'config' => ['redis' => ['host' => '127.0.0.1', 'port' => 6399]],
            ],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'block',
                'enable' => true,
                'config' => ['path:/wp-admin'],
            ]],
            'global' => ['mode' => 'exception'],
        ]]);

        $this->assertTrue($firewall->evaluate($this->getRequest('203.0.113.5')));
    }

    /**
     * And says why, in words that name the fix.
     *
     * "Class \"Redis\" not found" is true and is not the sentence somebody
     * needs: a missing extension and an unreachable server are different
     * problems with different fixes, and this is the only place that knows
     * which one happened.
     */
    public function testTheMissingExtensionIsNamedRatherThanTheClass(): void
    {
        new RedisStorage(['redis' => ['host' => '127.0.0.1', 'port' => 6399]]);

        $degraded = DegradedBackends::all();

        $this->assertCount(1, $degraded);
        $this->assertSame('block list', $degraded[0]['component']);
        $this->assertStringContainsString('redis extension is not installed', $degraded[0]['error']);
        $this->assertStringNotContainsString('not found', $degraded[0]['error']);
    }

    /**
     * The rate limit store degrades the same way.
     */
    public function testTheRateLimitStoreDegradesRatherThanFataling(): void
    {
        $storage = new RedisRateLimitStorage(['redis' => ['host' => '127.0.0.1', 'port' => 6399]]);

        $degraded = DegradedBackends::all();

        $this->assertCount(1, $degraded);
        $this->assertSame('rate limit', $degraded[0]['component']);
        $this->assertStringContainsString('redis extension is not installed', $degraded[0]['error']);

        // And the methods are safe afterwards, which is the half that is easy
        // to miss: the connection property is typed, so a failed construction
        // used to leave it *uninitialized*, and reading an uninitialized typed
        // property throws `\Error` — which the per-method `catch (\Exception)`
        // does not catch. Fixing only the constructor would have turned a boot
        // fatal into a fatal on the first request that counted anything.
        $storage->recordRequest('a-key', time());

        $this->assertSame(0, $storage->countRequests('a-key', 0, PHP_INT_MAX));
        $this->assertSame(0, $storage->forget('a-key', time()));
    }
}
