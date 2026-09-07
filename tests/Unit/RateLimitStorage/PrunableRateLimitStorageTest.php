<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\RateLimitStorage;

use Kanopi\Firewall\RateLimitStorage\CacheRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\PrunableRateLimitStorageInterface;
use Kanopi\Firewall\RateLimitStorage\RateLimitStorageInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * `forget()`, across every backend that implements it (#183).
 *
 * Written as one shared contract rather than four near-identical test classes:
 * the bug it fixes was that four backends independently never removed
 * anything, so the thing worth asserting is that they now all agree about
 * what "outside the window" means.
 */
class PrunableRateLimitStorageTest extends AbstractTestCase
{
    /**
     * Files and SQLite databases to remove after each test.
     *
     * @var array<int, string>
     */
    private array $tempFiles = [];

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
            @unlink($file . '.lock');
        }

        $this->tempFiles = [];

        parent::tearDown();
    }

    /**
     * The base interface must not have gained the method.
     *
     * `plugins[].metadata.storage.type` accepts any class implementing
     * `RateLimitStorageInterface`, so adding to it would fatal every direct
     * implementor on a `composer update`.
     */
    public function testTheBaseInterfaceIsUnchanged(): void
    {
        self::assertFalse((new \ReflectionClass(RateLimitStorageInterface::class))->hasMethod('forget'));
    }

    /**
     * Every shipped backend advertises the capability.
     */
    #[DataProvider('backendProvider')]
    public function testEveryShippedBackendCanPrune(string $kind): void
    {
        self::assertInstanceOf(PrunableRateLimitStorageInterface::class, $this->make($kind));
    }

    /**
     * Records older than the cutoff go; the rest stay.
     */
    #[DataProvider('backendProvider')]
    public function testRecordsOutsideTheWindowAreDropped(string $kind): void
    {
        $storage = $this->make($kind);
        $now = 1_700_000_000;

        foreach ([$now - 60, $now - 30, $now - 5, $now] as $timestamp) {
            $storage->recordRequest('rate:a', $timestamp);
        }

        self::assertSame(2, $storage->forget('rate:a', $now - 10));
        self::assertSame(2, $storage->countRequests('rate:a', 0, $now));
    }

    /**
     * A record exactly at the cutoff survives.
     *
     * `countRequests()` treats its `$start` as inclusive, so the plugin's
     * `$windowStart` is a timestamp the current window still counts. Dropping
     * it would lose a request and let a client exceed its limit by one.
     */
    #[DataProvider('backendProvider')]
    public function testARecordExactlyAtTheCutoffIsKept(string $kind): void
    {
        $storage = $this->make($kind);
        $now = 1_700_000_000;
        $windowStart = $now - 10;

        $storage->recordRequest('rate:a', $windowStart);

        self::assertSame(0, $storage->forget('rate:a', $windowStart));
        self::assertSame(
            1,
            $storage->countRequests('rate:a', $windowStart, $now),
            'The window counts its first second, so pruning must not drop it'
        );
    }

    /**
     * Other keys are left alone.
     *
     * The caller knows the window for the key it names and knows nothing about
     * anyone else's -- another key may be governed by a rule with a much wider
     * `sample`.
     */
    #[DataProvider('backendProvider')]
    public function testOtherKeysAreUntouched(string $kind): void
    {
        $storage = $this->make($kind);
        $now = 1_700_000_000;

        $storage->recordRequest('rate:a', $now - 60);
        $storage->recordRequest('rate:b', $now - 60);

        self::assertSame(1, $storage->forget('rate:a', $now - 10));
        self::assertSame(0, $storage->countRequests('rate:a', 0, $now));
        self::assertSame(1, $storage->countRequests('rate:b', 0, $now), 'The other key keeps its record');
    }

    /**
     * Pruning a key that was never recorded is a no-op, not an error.
     */
    #[DataProvider('backendProvider')]
    public function testAnUnknownKeyDropsNothing(string $kind): void
    {
        self::assertSame(0, $this->make($kind)->forget('rate:never-seen', time()));
    }

    /**
     * Pruning twice drops nothing the second time.
     */
    #[DataProvider('backendProvider')]
    public function testPruningIsIdempotent(string $kind): void
    {
        $storage = $this->make($kind);
        $now = 1_700_000_000;

        $storage->recordRequest('rate:a', $now - 60);

        self::assertSame(1, $storage->forget('rate:a', $now - 10));
        self::assertSame(0, $storage->forget('rate:a', $now - 10));
    }

    /**
     * Sustained traffic leaves storage bounded by the window, not by uptime.
     *
     * This is the property the whole issue is about, asserted the way an
     * operator would notice it was missing: keep going for a while and see
     * whether what is held keeps growing.
     */
    #[DataProvider('backendProvider')]
    public function testSustainedTrafficLeavesBoundedStorage(string $kind): void
    {
        $storage = $this->make($kind);
        $start = 1_700_000_000;
        $sample = 10;

        // 600 requests at 10/second: a minute of traffic through a 10s window.
        for ($i = 0; $i < 600; $i++) {
            $now = $start + intdiv($i, 10);
            $storage->forget('rate:a', $now - $sample);
            $storage->recordRequest('rate:a', $now);
        }

        $held = $storage->countRequests('rate:a', 0, PHP_INT_MAX);

        self::assertLessThanOrEqual(
            (($sample + 1) * 10),
            $held,
            'Only the window should be held, however long the traffic runs'
        );
        self::assertGreaterThan(0, $held, 'The current window is still counted');
    }

    /**
     * The file backend writes the pruned state to disk.
     *
     * Inherited unchanged from `InMemoryRateLimitStorage` this would filter
     * the in-memory copy and be thrown away by the next `loadFile()`, leaving
     * the file exactly as large as it was -- so the one backend that most
     * needed the fix would silently not have it.
     */
    public function testTheFileBackendPersistsThePrunedState(): void
    {
        $file = $this->tempFile('json');
        $storage = new FileRateLimitStorage(['file' => $file]);
        $now = 1_700_000_000;

        foreach ([$now - 60, $now - 30, $now] as $timestamp) {
            $storage->recordRequest('rate:a', $timestamp);
        }

        $sizeBefore = filesize($file);
        $storage->forget('rate:a', $now - 10);
        clearstatcache(true, $file);

        self::assertLessThan($sizeBefore, filesize($file), 'The file should have shrunk');
        self::assertSame(
            1,
            (new FileRateLimitStorage(['file' => $file]))->countRequests('rate:a', 0, $now),
            'A fresh instance reading the file must see the pruned state'
        );
    }

    /**
     * An emptied key is removed rather than left behind as an empty list.
     *
     * A rate key carries a client address, so a busy site sees an unbounded
     * number of distinct keys over time. Keeping an empty entry for each would
     * trade growing values for a growing key set.
     */
    public function testAnEmptiedKeyIsRemovedEntirely(): void
    {
        $storage = new InMemoryRateLimitStorage();
        $storage->recordRequest('rate:a', 1_700_000_000);
        $storage->forget('rate:a', 1_700_000_100);

        $requests = (new \ReflectionProperty(InMemoryRateLimitStorage::class, 'requests'))->getValue($storage);

        self::assertSame([], $requests);
    }

    /**
     * The cache backend deletes an emptied item rather than storing `[]`.
     */
    public function testTheCacheBackendDeletesAnEmptiedItem(): void
    {
        $adapter = new ArrayAdapter();
        $storage = new CacheRateLimitStorage(['adaptor' => $adapter]);

        $storage->recordRequest('rate:a', 1_700_000_000);
        self::assertTrue($adapter->hasItem('rate__a'));

        $storage->forget('rate:a', 1_700_000_100);
        self::assertFalse($adapter->hasItem('rate__a'), 'An empty entry would hold the key for its whole TTL');
    }

    /**
     * A cache backend with no adaptor reports rather than fataling.
     */
    public function testTheCacheBackendWithoutAnAdaptorDropsNothing(): void
    {
        self::assertSame(0, (new CacheRateLimitStorage([]))->forget('rate:a', time()));
    }

    /**
     * A cache entry holding something that is not a list is left alone.
     */
    public function testTheCacheBackendIgnoresAnEntryItDidNotWrite(): void
    {
        $adapter = new ArrayAdapter();
        $adapter->save($adapter->getItem('rate__a')->set('not-a-list'));

        self::assertSame(0, (new CacheRateLimitStorage(['adaptor' => $adapter]))->forget('rate:a', time()));
    }

    /**
     * The database table is created with an index for the query it serves.
     *
     * `countRequests()` and `forget()` both filter on `rule` and range over
     * `timestamp`. Without an index both are full scans, which is what made an
     * unbounded table expensive rather than merely large.
     */
    public function testTheDatabaseTableIndexesRuleAndTimestamp(): void
    {
        $path = $this->tempFile('sqlite');
        new DatabaseRateLimitStorage(['connection' => ['driver' => 'pdo_sqlite', 'path' => $path]]);

        $connection = \Doctrine\DBAL\DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $path]);
        $indexes = $connection->createSchemaManager()->listTableIndexes('firewall_rate_limit_storage');

        $columns = [];
        foreach ($indexes as $index) {
            $columns[] = $index->getColumns();
        }

        self::assertContains(['rule', 'timestamp'], $columns);
    }

    /**
     * A database failure is reported and survived, not propagated.
     *
     * Pruning is housekeeping: a rate limit that still counts correctly
     * against a table it could not tidy is working.
     */
    public function testADatabaseFailureIsSurvived(): void
    {
        $path = $this->tempFile('sqlite');
        $storage = new DatabaseRateLimitStorage(['connection' => ['driver' => 'pdo_sqlite', 'path' => $path]]);
        $storage->recordRequest('rate:a', 1_700_000_000);

        \Doctrine\DBAL\DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $path])
            ->executeStatement('DROP TABLE firewall_rate_limit_storage');

        self::assertSame(0, $storage->forget('rate:a', 1_700_000_100));
    }

    /**
     * Backends that implement the capability and can be built in a unit test.
     *
     * Redis is covered in `tests/Integration/RateLimitStorage` against a real
     * server, because what `ZREMRANGEBYSCORE` does to a sorted set is exactly
     * the thing a mock cannot tell you.
     *
     * @return array<string, array{string}>
     *   Provider sets, keyed by backend.
     */
    public static function backendProvider(): array
    {
        return [
            'memory' => ['memory'],
            'file' => ['file'],
            'database' => ['database'],
            'cache' => ['cache'],
        ];
    }

    /**
     * Build one of the backends under test.
     */
    private function make(string $kind): RateLimitStorageInterface&PrunableRateLimitStorageInterface
    {
        return match ($kind) {
            'file' => new FileRateLimitStorage(['file' => $this->tempFile('json')]),
            'database' => new DatabaseRateLimitStorage([
                'connection' => ['driver' => 'pdo_sqlite', 'path' => $this->tempFile('sqlite')],
            ]),
            'cache' => new CacheRateLimitStorage(['adaptor' => new ArrayAdapter()]),
            default => new InMemoryRateLimitStorage(),
        };
    }

    /**
     * Return a temporary path this test will clean up.
     */
    private function tempFile(string $extension): string
    {
        $file = sys_get_temp_dir() . '/fw-prunable-' . uniqid('', true) . '.' . $extension;
        $this->tempFiles[] = $file;

        return $file;
    }
}
