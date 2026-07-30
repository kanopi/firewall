<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Search and prune by address (#26).
 *
 * Covers InMemoryStorage and FileStorage together, since FileStorage inherits
 * the behaviour and only adds locking and persistence around it. DatabaseStorage
 * is exercised in DatabaseStorageTest against its mocked connection.
 */
final class QueryableStorageTest extends AbstractTestCase
{
    /**
     * @var array<int, string>
     */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            @unlink($file);
            @unlink($file . '.lock');
            @unlink(dirname($file) . '/storage_data_offenses.json');
            @unlink(dirname($file) . '/storage_data_offenses.json.lock');
        }

        $this->tempFiles = [];

        parent::tearDown();
    }

    private function fileStorage(): FileStorage
    {
        $file = sys_get_temp_dir() . '/fw-queryable-' . uniqid('', true) . '.json';
        $this->tempFiles[] = $file;

        return new FileStorage(['storage_file' => $file]);
    }

    /**
     * Seed a storage with a spread of addresses across two ranges plus IPv6.
     */
    private function seed(StorageInterface $storage): void
    {
        foreach (
            [
            '203.0.113.5',
            '203.0.113.99',
            '198.51.100.7',
            '2001:db8::1',
            '2001:db8::ff',
            '8.8.8.8',
            ] as $address
        ) {
            $storage->set($address, ['event_id' => 'evt-' . $address]);
        }
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideStorageKinds(): array
    {
        return ['memory' => ['memory'], 'file' => ['file']];
    }

    private function make(string $kind): InMemoryStorage
    {
        return $kind === 'file' ? $this->fileStorage() : new InMemoryStorage();
    }

    /**
     * Backdate a record's expiry so it is lapsed but not yet collected.
     *
     * Beats sleeping. For FileStorage the change also has to be written to
     * disk: its find() deliberately reloads from the file, so an in-memory
     * mutation alone would be discarded before the assertion ever ran.
     */
    private function backdate(InMemoryStorage $storage, string $address): void
    {
        $property = new \ReflectionProperty(InMemoryStorage::class, 'store');
        $store = $property->getValue($storage);
        $store[$address]['expire'] = time() - 60;
        $property->setValue($storage, $store);

        if ($storage instanceof FileStorage) {
            $persist = new \ReflectionMethod(FileStorage::class, 'persistStorageFile');
            $persist->invoke($storage);
        }
    }

    // -----------------------------------------------------------------------
    // Capability
    // -----------------------------------------------------------------------

    /**
     * The whole point of a capability interface is that callers can detect it.
     */
    #[DataProvider('provideStorageKinds')]
    public function testStoragesAdvertiseTheCapability(string $kind): void
    {
        $this->assertInstanceOf(QueryableStorageInterface::class, $this->make($kind));
    }

    /**
     * StorageInterface must NOT gain these methods — that would fatal every
     * third-party implementation on upgrade, which is why they live on a
     * separate interface.
     */
    public function testStorageInterfaceIsUnchanged(): void
    {
        $reflection = new \ReflectionClass(StorageInterface::class);

        $this->assertFalse($reflection->hasMethod('find'));
        $this->assertFalse($reflection->hasMethod('deleteMatching'));
    }

    // -----------------------------------------------------------------------
    // find()
    // -----------------------------------------------------------------------

    #[DataProvider('provideStorageKinds')]
    public function testFindByExactAddress(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $found = $storage->find('203.0.113.5');

        $this->assertSame(['203.0.113.5'], array_keys($found));
    }

    #[DataProvider('provideStorageKinds')]
    public function testFindByCidrRange(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $found = $storage->find('203.0.113.0/24');

        $this->assertEqualsCanonicalizing(['203.0.113.5', '203.0.113.99'], array_keys($found));
    }

    #[DataProvider('provideStorageKinds')]
    public function testFindMatchesIpv6Ranges(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $found = $storage->find('2001:db8::/32');

        $this->assertEqualsCanonicalizing(['2001:db8::1', '2001:db8::ff'], array_keys($found));
    }

    #[DataProvider('provideStorageKinds')]
    public function testFindReturnsExpiryAndOffenseCount(string $kind): void
    {
        $storage = $this->make($kind);
        $storage->set('203.0.113.5', ['event_id' => 'evt'], 3600);

        $found = $storage->find('203.0.113.5');

        $this->assertArrayHasKey('expire', $found['203.0.113.5']);
        $this->assertArrayHasKey('expires_at', $found['203.0.113.5']);
        $this->assertGreaterThan(time(), $found['203.0.113.5']['expire']);
        // set() records an offense, so an operator asking "why is this
        // blocked?" sees the history alongside the block.
        $this->assertSame(1, $found['203.0.113.5']['offenses']);
    }

    /**
     * A lapsed block is not in force, and showing one to an operator
     * investigating a complaint sends them down the wrong path.
     */
    #[DataProvider('provideStorageKinds')]
    public function testFindExcludesExpiredRecords(string $kind): void
    {
        $storage = $this->make($kind);
        $storage->set('203.0.113.5', ['event_id' => 'evt'], 3600);
        $storage->set('203.0.113.6', ['event_id' => 'evt'], 3600);

        $this->backdate($storage, '203.0.113.5');

        $found = $storage->find('203.0.113.0/24');

        $this->assertSame(['203.0.113.6'], array_keys($found));
    }

    #[DataProvider('provideStorageKinds')]
    public function testFindReturnsEmptyWhenNothingMatches(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $this->assertSame([], $storage->find('10.0.0.0/8'));
    }

    /**
     * A malformed pattern must match nothing rather than everything — the
     * caller's next move is usually to delete what came back.
     *
     * @param string $pattern
     */
    #[DataProvider('provideMalformedPatterns')]
    public function testFindRejectsMalformedPatterns(string $pattern): void
    {
        $storage = new InMemoryStorage();
        $this->seed($storage);

        $this->assertSame([], $storage->find($pattern), sprintf('Pattern "%s" should match nothing.', $pattern));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideMalformedPatterns(): array
    {
        return [
            'empty' => [''],
            'not an address' => ['nonsense'],
            'bare wildcard' => ['*'],
            'sql-ish wildcard' => ['%'],
            'partial address' => ['203.0.113.'],
            'missing prefix' => ['203.0.113.0/'],
            'non-numeric prefix' => ['203.0.113.0/abc'],
            'ipv4 prefix out of range' => ['203.0.113.0/33'],
            'ipv6 prefix out of range' => ['2001:db8::/129'],
            'negative prefix' => ['203.0.113.0/-1'],
        ];
    }

    /**
     * `/33` is a typo, not a range. Left unvalidated it degrades to a
     * single-host match, so an operator would clear one record believing they
     * had cleared 512.
     */
    public function testOutOfRangePrefixDoesNotDegradeToHostMatch(): void
    {
        $storage = new InMemoryStorage();
        $this->seed($storage);

        $this->assertSame([], $storage->find('203.0.113.5/33'));
        $this->assertSame(0, $storage->deleteMatching(['203.0.113.5/33']));
        $this->assertTrue($storage->exists('203.0.113.5'));
    }

    // -----------------------------------------------------------------------
    // deleteMatching()
    // -----------------------------------------------------------------------

    #[DataProvider('provideStorageKinds')]
    public function testDeleteMatchingByCidr(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $deleted = $storage->deleteMatching(['203.0.113.0/24']);

        $this->assertSame(2, $deleted);
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertFalse($storage->exists('203.0.113.99'));
        // Everything outside the range is untouched.
        $this->assertTrue($storage->exists('198.51.100.7'));
        $this->assertTrue($storage->exists('8.8.8.8'));
    }

    #[DataProvider('provideStorageKinds')]
    public function testDeleteMatchingAcceptsMultiplePatterns(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $deleted = $storage->deleteMatching(['203.0.113.0/24', '8.8.8.8']);

        $this->assertSame(3, $deleted);
        $this->assertTrue($storage->exists('198.51.100.7'));
    }

    /**
     * An address covered by two patterns is one deletion, not two.
     */
    #[DataProvider('provideStorageKinds')]
    public function testOverlappingPatternsCountEachRecordOnce(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $this->assertSame(2, $storage->deleteMatching(['203.0.113.0/24', '203.0.113.5']));
    }

    /**
     * One bad range must not strand the good ones. An operator pasting twenty
     * CIDRs should not have nineteen blocks silently left in place because of
     * a typo in the tenth.
     */
    #[DataProvider('provideStorageKinds')]
    public function testMalformedPatternDoesNotAbortTheRest(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $deleted = $storage->deleteMatching(['not-an-address', '203.0.113.0/24', '203.0.113.0/33']);

        $this->assertSame(2, $deleted);
        $this->assertFalse($storage->exists('203.0.113.5'));
    }

    #[DataProvider('provideStorageKinds')]
    public function testDeleteMatchingWithNoValidPatternsDeletesNothing(string $kind): void
    {
        $storage = $this->make($kind);
        $this->seed($storage);

        $this->assertSame(0, $storage->deleteMatching([]));
        $this->assertSame(0, $storage->deleteMatching(['garbage', '']));
        $this->assertTrue($storage->exists('203.0.113.5'));
    }

    /**
     * Offense history goes with the block. Left behind, `blocking_escalation`
     * would escalate a just-un-blocked address straight back to a longer ban
     * on its next request, and the un-block would appear not to have worked.
     */
    #[DataProvider('provideStorageKinds')]
    public function testDeleteMatchingClearsOffenseHistory(string $kind): void
    {
        $storage = $this->make($kind);

        $storage->set('203.0.113.5', ['event_id' => 'evt']);
        $storage->recordOffense('203.0.113.5');
        $this->assertGreaterThan(0, $storage->countOffenses('203.0.113.5'));

        $storage->deleteMatching(['203.0.113.0/24']);

        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
    }

    /**
     * Unlike find(), an un-block must reach a record whose expiry has already
     * lapsed but which has not yet been collected — otherwise the operator is
     * told nothing matched while the row is still on disk.
     */
    public function testDeleteMatchingReachesExpiredRecords(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('203.0.113.5', ['event_id' => 'evt'], 3600);

        $this->backdate($storage, '203.0.113.5');

        $this->assertSame([], $storage->find('203.0.113.5'));
        $this->assertSame(1, $storage->deleteMatching(['203.0.113.5']));
    }

    // -----------------------------------------------------------------------
    // FileStorage specifics
    // -----------------------------------------------------------------------

    /**
     * Regression guard for a self-deadlock.
     *
     * FileStorage::deleteMatching() holds an exclusive lock on the storage
     * file. withExclusiveLock() opens a fresh handle per call and flock()
     * locks attach to the open file description, so if the deletion routed
     * through FileStorage::delete() — which takes the same lock — the process
     * would block on a lock it already holds and hang forever.
     *
     * Verified independently: a second LOCK_EX|LOCK_NB on the same path in one
     * process returns false. This test would hang rather than fail if the
     * implementation regressed, so it is bounded by the suite timeout.
     */
    public function testFileStorageDeleteMatchingDoesNotDeadlock(): void
    {
        $storage = $this->fileStorage();
        $this->seed($storage);

        $deleted = $storage->deleteMatching(['203.0.113.0/24']);

        $this->assertSame(2, $deleted);
    }

    /**
     * The deletion has to survive the process, not just the request.
     */
    public function testFileStorageDeletionIsPersisted(): void
    {
        $file = sys_get_temp_dir() . '/fw-queryable-' . uniqid('', true) . '.json';
        $this->tempFiles[] = $file;

        $storage = new FileStorage(['storage_file' => $file]);
        $this->seed($storage);
        $storage->deleteMatching(['203.0.113.0/24']);

        // A second instance reads from disk, so this only passes if the
        // deletion was actually written rather than left in memory.
        $reopened = new FileStorage(['storage_file' => $file]);

        $this->assertFalse($reopened->exists('203.0.113.5'));
        $this->assertTrue($reopened->exists('198.51.100.7'));
    }

    /**
     * FileStorage::find() must read from disk, not from whatever this
     * instance happened to load at construction.
     */
    public function testFileStorageFindReadsFromDisk(): void
    {
        $file = sys_get_temp_dir() . '/fw-queryable-' . uniqid('', true) . '.json';
        $this->tempFiles[] = $file;

        $writer = new FileStorage(['storage_file' => $file]);
        $reader = new FileStorage(['storage_file' => $file]);

        $writer->set('203.0.113.5', ['event_id' => 'evt']);

        $this->assertSame(['203.0.113.5'], array_keys($reader->find('203.0.113.0/24')));
    }

    /**
     * A stored key that is not an address must never be returned to a caller
     * who is about to delete what came back.
     */
    public function testNonAddressKeysAreNeverMatched(): void
    {
        $storage = new InMemoryStorage();
        $storage->set('not-an-ip', ['event_id' => 'evt']);
        $storage->set('203.0.113.5', ['event_id' => 'evt']);

        $this->assertSame(['203.0.113.5'], array_keys($storage->find('0.0.0.0/0')));
        $this->assertSame(1, $storage->deleteMatching(['0.0.0.0/0']));
        $this->assertTrue($storage->exists('not-an-ip'));
    }
}
