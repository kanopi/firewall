<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\ConcurrencyGaugeInterface;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Counting concurrency atomically (#329).
 */
class ConcurrencyGaugeTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-gauge-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->dir . '/*') as $path) {
            if (is_string($path)) {
                is_dir($path) ? @rmdir($path) : @unlink($path);
            }
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * Incrementing a PHP array is perfectly atomic within one process, and a
     * cap across php-fpm workers is exactly what one process cannot see. So it
     * must not implement the interface — a rule configured against it refuses
     * to start, which is loud, rather than running uncapped, which looks like
     * it is working.
     */
    public function testInMemoryStorageDeliberatelyCannotCount(): void
    {
        $this->assertNotInstanceOf(ConcurrencyGaugeInterface::class, new InMemoryStorage([]));
    }

    /**
     * Not implemented rather than approximated. Neither DBAL's portable SQL nor
     * a read-then-write gives an atomic increment across every driver this
     * supports, and an increment that is not atomic under-counts.
     */
    public function testDatabaseStorageDoesNotClaimToCount(): void
    {
        $this->assertFalse(is_a(DatabaseStorage::class, ConcurrencyGaugeInterface::class, true));
    }

    public function testFileAndRedisStorageBothCount(): void
    {
        $this->assertTrue(is_a(FileStorage::class, ConcurrencyGaugeInterface::class, true));
        $this->assertTrue(is_a(RedisStorage::class, ConcurrencyGaugeInterface::class, true));
    }

    public function testEnteringAndLeavingCountsUpAndDown(): void
    {
        $storage = $this->fileStorage();

        $this->assertSame(0, $storage->inFlight('tarpit'));
        $this->assertSame(1, $storage->enter('tarpit', 60));
        $this->assertSame(2, $storage->enter('tarpit', 60));
        $this->assertSame(2, $storage->inFlight('tarpit'));

        $storage->leave('tarpit');

        $this->assertSame(1, $storage->inFlight('tarpit'));
    }

    /**
     * A caller releasing in a `finally` cannot always know whether its claim
     * succeeded, and the alternative to tolerating that is a leak on every
     * error path.
     */
    public function testLeavingMoreOftenThanEnteringNeverGoesNegative(): void
    {
        $storage = $this->fileStorage();

        $storage->leave('tarpit');
        $storage->leave('tarpit');

        $this->assertSame(0, $storage->inFlight('tarpit'));
        $this->assertSame(1, $storage->enter('tarpit', 60));
    }

    public function testTwoKeysAreCountedSeparately(): void
    {
        $storage = $this->fileStorage();

        $storage->enter('tarpit', 60);
        $storage->enter('tarpit', 60);
        $storage->enter('something-else', 60);

        $this->assertSame(2, $storage->inFlight('tarpit'));
        $this->assertSame(1, $storage->inFlight('something-else'));
    }

    /**
     * Two handles on one file, which is what two php-fpm workers are. The count
     * has to be shared, or the cap is per-process and counts nothing useful.
     */
    public function testTheCountIsSharedBetweenSeparateInstances(): void
    {
        $first = $this->fileStorage();
        $second = $this->fileStorage();

        $this->assertSame(1, $first->enter('tarpit', 60));
        $this->assertSame(2, $second->enter('tarpit', 60), 'The second instance did not see the first');

        $second->leave('tarpit');

        $this->assertSame(1, $first->inFlight('tarpit'));
    }

    /**
     * The backstop for a worker killed between `enter()` and `leave()`. While
     * it has not expired, the leaked count makes the cap stricter — the safe
     * direction — and then it clears.
     */
    public function testAStaleCountExpires(): void
    {
        $storage = $this->fileStorage();

        $storage->enter('tarpit', 60);
        $storage->enter('tarpit', 60);

        $this->ageTheGauge('tarpit', 120);

        $this->assertSame(1, $storage->enter('tarpit', 60), 'A count older than its ttl should read as zero');
    }

    /**
     * `inFlight()` reports what is written without applying a ttl, so a stale
     * count still reads high until something claims. That is deliberate: the
     * cap is enforced by `enter()`, and a report that quietly zeroed itself
     * would hide a leak rather than show it.
     */
    public function testAStaleCountIsStillReportedUntilSomethingClaims(): void
    {
        $storage = $this->fileStorage();
        $storage->enter('tarpit', 60);
        $this->ageTheGauge('tarpit', 120);

        $this->assertSame(1, $storage->inFlight('tarpit'));
    }

    /**
     * An increment that is not atomic under-counts, the cap admits more holds
     * than it allows, and that is the self-DoS. So a gauge file that cannot be
     * opened reports the zero the interface reserves for "could not be
     * counted", rather than a number.
     */
    public function testAGaugeThatCannotBeOpenedReportsThatItCouldNot(): void
    {
        $storage = $this->fileStorage();

        // A directory exactly where the counter file belongs. `fopen()` for
        // writing refuses a directory for root and everybody else alike, which
        // an unwritable parent would not.
        mkdir($this->dir . '/blocked.data.gauge.' . hash('sha256', 'tarpit') . '.txt');

        $this->assertSame(0, $storage->enter('tarpit', 60), 'A count it could not take must read as zero');
        $this->assertSame(0, $storage->inFlight('tarpit'));

        // And a key it *can* open is unaffected.
        $this->assertSame(1, $storage->enter('something-else', 60));
    }

    /**
     * A filesystem without working locks — an NFS mount with no lock daemon —
     * is real, and not something a test can provoke against a working one. What
     * matters is what happens next: refuse, rather than proceed unlocked. An
     * increment that is not atomic under-counts and the cap stops holding.
     */
    public function testAGaugeThatCannotBeLockedRefusesRatherThanCountingAnyway(): void
    {
        $storage = new class ([
            'storage_file' => $this->dir . '/blocked.data',
            'offense_file' => $this->dir . '/offenses.json',
        ]) extends FileStorage {
            protected function lockGauge($handle): bool
            {
                return false;
            }
        };

        $this->assertSame(0, $storage->enter('tarpit', 60));
        $this->assertSame(0, $storage->inFlight('tarpit'));
    }

    /**
     * Beside the block list rather than inside it: a counter touched on every
     * hold has no business in a file whose write amplification is the size of
     * the block list.
     */
    public function testTheCounterDoesNotLiveInTheBlockList(): void
    {
        $storage = $this->fileStorage();
        $storage->set('203.0.113.9', ['request' => []], 600);
        $storage->enter('tarpit', 60);

        $blockList = (string) file_get_contents($this->dir . '/blocked.data');

        $this->assertStringContainsString('203.0.113.9', $blockList);
        $this->assertStringNotContainsString('tarpit', $blockList);
    }

    private function fileStorage(): FileStorage
    {
        return new FileStorage([
            'storage_file' => $this->dir . '/blocked.data',
            'offense_file' => $this->dir . '/offenses.json',
        ]);
    }

    /**
     * Rewrite a gauge file's timestamp so it reads as older than it is.
     */
    private function ageTheGauge(string $key, int $secondsAgo): void
    {
        $path = $this->dir . '/blocked.data.gauge.' . hash('sha256', $key) . '.txt';
        $contents = (string) file_get_contents($path);
        [$count] = explode(':', $contents, 2);

        file_put_contents($path, $count . ':' . (time() - $secondsAgo));
    }
}
