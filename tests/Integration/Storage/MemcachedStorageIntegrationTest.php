<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration\Storage;

use Kanopi\Firewall\Storage\MemcachedStorage;
use Kanopi\Firewall\Tests\Integration\IntegrationTestCase;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\Firewall\Utility\DegradedBackends;
use Memcached;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;

/**
 * Exercises the Memcached block list against a real Memcached (#392).
 *
 * The unit tests run against an in-process fake, which proves the logic and nothing about
 * the server: that an item's expiry really drops it, that an expiry past 30 days is really
 * read as a timestamp, that compare-and-swap really refuses a stale token, and that the
 * index really survives several processes writing it at once. Those are what this checks.
 *
 * CI runs a Memcached service and installs `ext-memcached`. Locally it skips unless one is
 * reachable at MEMCACHED_HOST / MEMCACHED_PORT.
 */
#[RequiresPhpExtension('memcached')]
final class MemcachedStorageIntegrationTest extends IntegrationTestCase
{
    /**
     * A prefix unique to this run, so a shared Memcached stays usable.
     */
    private string $prefix;

    /**
     * Whether setUp() found a server, so tearDown() only cleans one that exists.
     */
    private bool $reachable = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->skipIfGroupDisabled('memcached');
        $this->prefix = 'fwtest:' . bin2hex(random_bytes(6)) . ':';
        DegradedBackends::reset();

        if (!$this->memcachedIsReachable()) {
            $this->markTestSkipped('No Memcached server reachable with the configured settings.');
        }

        $this->reachable = true;
    }

    protected function tearDown(): void
    {
        // Leave the server as it was found. reset() clears only this run's
        // prefix -- which is also one of the things under test.
        if ($this->reachable) {
            $this->storage()->reset();
        }

        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private function options(): array
    {
        $config = self::getMemcachedConfig();

        return [
            'host' => (string) $config['host'],
            'port' => (int) $config['port'],
            'prefix' => $this->prefix,
        ];
    }

    private function storage(): MemcachedStorage
    {
        return new MemcachedStorage(['memcached' => $this->options()]);
    }

    private function client(): Memcached
    {
        $config = self::getMemcachedConfig();
        $memcached = new Memcached();
        $memcached->setOption(Memcached::OPT_CONNECT_TIMEOUT, 500);
        $memcached->addServer((string) $config['host'], (int) $config['port']);

        return $memcached;
    }

    private function memcachedIsReachable(): bool
    {
        return $this->client()->getVersion() !== false;
    }

    public function testItConnects(): void
    {
        $this->storage();

        $this->assertSame([], DegradedBackends::all());
    }

    public function testABlockRoundTrips(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'test', 'nested' => ['a' => 1]], 300);

        $this->assertSame(['reason' => 'test', 'nested' => ['a' => 1]], $storage->get('203.0.113.5'));
        $this->assertTrue($storage->exists('203.0.113.5'));
    }

    /**
     * Expiry is the server's job, and it does it.
     */
    public function testTheServerExpiresABlock(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'brief'], 1);

        sleep(2);

        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertSame([], $storage->find('203.0.113.0/24'));
    }

    /**
     * Past 30 days Memcached reads an expiry as a timestamp. Passed through as seconds,
     * a 90-day ban would be a moment in 1970 and gone as soon as it was written.
     */
    public function testABanLongerThanThirtyDaysSurvivesBeingWritten(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'long'], 90 * 86400);

        $this->assertTrue($this->storage()->exists('203.0.113.5'));

        $found = $storage->find('203.0.113.5');
        $this->assertEqualsWithDelta(time() + 90 * 86400, $found['203.0.113.5']['expire'], 2);
    }

    public function testExtendingABanLengthensIt(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'x'], 1);

        $this->assertTrue($storage->addToExpire('203.0.113.5', 60));

        sleep(2);

        $this->assertTrue($storage->exists('203.0.113.5'), 'Extended past its original lifetime');
    }

    /**
     * Offenses outlive the block, as on every backend; escalation needs the history.
     */
    public function testOffensesOutliveTheBlock(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'x'], 1);
        $storage->recordOffense('203.0.113.5');

        sleep(2);

        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertSame(2, $storage->countOffenses('203.0.113.5'));
    }

    public function testFindAndDeleteMatchingByRange(): void
    {
        $storage = $this->storage();

        foreach (['203.0.113.5', '203.0.113.99', '198.51.100.7', '2001:db8::1'] as $address) {
            $storage->set($address, ['reason' => $address], 300);
        }

        $this->assertCount(2, $storage->find('203.0.113.0/24'));
        $this->assertSame(['2001:db8::1'], array_keys($storage->find('2001:db8::/32')));

        $this->assertSame(2, $storage->deleteMatching(['203.0.113.0/24']));
        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertTrue($storage->exists('198.51.100.7'));
    }

    /**
     * Enough blocks that the index shards hold real volume, all found again.
     */
    public function testFindEnumeratesEveryShard(): void
    {
        $storage = $this->storage();

        for ($i = 0; $i < 600; $i++) {
            $storage->set('10.0.' . intdiv($i, 256) . '.' . ($i % 256), ['reason' => 'bulk'], 120);
        }

        $this->assertCount(600, $storage->find('10.0.0.0/8'));
        $this->assertNull($storage->enumerationGap());
    }

    /**
     * An evicted shard is reported, and an exact address is still answered.
     */
    public function testAnEvictedShardIsReportedAndAnExactLookupStillWorks(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'x'], 300);

        $this->client()->delete($this->prefix . 'index:' . (crc32('203.0.113.5') % MemcachedStorage::INDEX_SHARDS));

        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertNotNull($storage->enumerationGap());
        $this->assertSame(['203.0.113.5'], array_keys($storage->find('203.0.113.5')));
        $this->assertSame(1, $storage->deleteMatching(['203.0.113.5']));
    }

    /**
     * The gap reaches the operator: `BlockList::backend()` carries it.
     */
    public function testTheGapIsReportedThroughTheBlockList(): void
    {
        $config = ['storage' => [
            'type' => MemcachedStorage::class,
            'config' => ['memcached' => $this->options()],
        ]];

        $this->storage()->set('203.0.113.5', ['reason' => 'x'], 300);
        $this->assertNull((new BlockList([$config]))->backend()['gap']);

        $this->client()->delete($this->prefix . 'index:meta');

        $backend = (new BlockList([$config]))->backend();
        $this->assertTrue($backend['queryable']);
        $this->assertTrue($backend['durable']);
        $this->assertStringContainsString('meta key', (string) $backend['gap']);
    }

    public function testResetClearsOnlyOurNamespace(): void
    {
        $neighbour = $this->prefix . 'neighbour';
        $this->client()->set($neighbour, 'theirs');

        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'x'], 300);
        $storage->set('fw_challenge_revoked:abc', ['consumed_at' => 1], 300);

        $this->assertTrue($storage->reset());

        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertFalse($storage->exists('fw_challenge_revoked:abc'));
        $this->assertSame('theirs', $this->client()->get($neighbour));

        $this->client()->delete($neighbour);
    }

    /**
     * Several processes blocking at once lose nothing from the index.
     *
     * The reason every index write is a compare-and-swap. Separate processes rather than
     * one looping, because only a real race between connections proves the server is
     * refusing the stale swap -- a single process never has a stale token to offer.
     */
    public function testConcurrentWritersLoseNothing(): void
    {
        $workers = 4;
        $each = 100;
        $script = tempnam(sys_get_temp_dir(), 'fw-memcached-writer-') . '.php';

        file_put_contents($script, sprintf(
            <<<'PHP'
            <?php
            require %s;
            $storage = new \Kanopi\Firewall\Storage\MemcachedStorage(['memcached' => json_decode(%s, true)]);
            $worker = (int) $argv[1];
            for ($i = 0; $i < %d; $i++) {
                $storage->set(sprintf('10.%%d.%%d.%%d', $worker, intdiv($i, 256), $i %% 256), ['w' => $worker], 300);
            }
            echo count(\Kanopi\Firewall\Utility\DegradedBackends::all());
            PHP,
            var_export(dirname(__DIR__, 3) . '/vendor/autoload.php', true),
            var_export(json_encode($this->options()), true),
            $each
        ));

        $processes = [];

        try {
            for ($worker = 0; $worker < $workers; $worker++) {
                // display_errors=stderr, as FirewallBlockCommandTest does: the CI
                // image prints "Module ... is already loaded" to stdout on every
                // PHP start, which would otherwise arrive ahead of the count.
                $process = proc_open(
                    [PHP_BINARY, '-d', 'display_errors=stderr', $script, (string) $worker],
                    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                    $pipes
                );
                $this->assertIsResource($process);
                $processes[] = [$process, $pipes];
            }

            foreach ($processes as [$process, $pipes]) {
                $degraded = stream_get_contents($pipes[1]);
                $errors = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);

                $this->assertSame(0, proc_close($process), 'A writer failed: ' . $errors);
                $this->assertSame('0', trim((string) $degraded), 'A writer gave up on the index');
            }
        } finally {
            @unlink($script);
        }

        $this->assertCount($workers * $each, $this->storage()->find('10.0.0.0/8'));
    }
}
