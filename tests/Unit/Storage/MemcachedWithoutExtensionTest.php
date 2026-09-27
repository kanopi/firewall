<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Storage\MemcachedStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Memcached configured where it cannot be used (#392).
 *
 * The same shape as #356 for Redis: `new Memcached()` without the extension throws `\Error`,
 * which a `catch (\Exception)` does not catch, and a firewall that does not start is no
 * protection at all. These run on a host **without** the extension and skip where it is
 * loaded, because the assertion is about its absence.
 */
final class MemcachedWithoutExtensionTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (extension_loaded('memcached')) {
            $this->markTestSkipped('This asserts what happens without ext-memcached, and it is loaded here.');
        }

        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    public function testTheFirewallStartsWithoutTheExtension(): void
    {
        $firewall = Firewall::create([[
            'storage' => [
                'type' => MemcachedStorage::class,
                'config' => ['memcached' => ['host' => '127.0.0.1', 'port' => 11299]],
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
     * And names the fix, rather than `Class "Memcached" not found`.
     */
    public function testTheMissingExtensionIsNamedRatherThanTheClass(): void
    {
        $storage = new MemcachedStorage(['memcached' => ['host' => '127.0.0.1', 'port' => 11299]]);

        $degraded = DegradedBackends::all();

        $this->assertCount(1, $degraded);
        $this->assertSame('block list', $degraded[0]['component']);
        $this->assertStringContainsString('memcached extension is not installed', $degraded[0]['error']);
        $this->assertStringNotContainsString('not found', $degraded[0]['error']);

        $this->assertFalse($storage->set('203.0.113.5', ['a' => 1], 60));
        $this->assertNull($storage->get('203.0.113.5'));
        $this->assertNotNull($storage->enumerationGap());
    }
}
