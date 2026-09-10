<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Storage\NonQueryableStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\BlockList;

/**
 * Reading and lifting blocks from a configuration (#291).
 *
 * Against a real `FileStorage`, because what is under test is whether the
 * questions an operator asks reach the backend that has been able to answer
 * them since 2.19.0.
 */
class BlockListTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-blocklist-' . uniqid();
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private function fileConfig(): array
    {
        return [
            'global' => ['mode' => 'block'],
            'storage' => [
                'type' => FileStorage::class,
                'config' => ['storage_file' => $this->dir . '/blocked.data'],
            ],
            'plugins' => [],
        ];
    }

    /**
     * Put some blocks in the store the configuration points at.
     */
    private function seed(): FileStorage
    {
        $storage = new FileStorage(['storage_file' => $this->dir . '/blocked.data']);

        $storage->set('203.0.113.5', ['request' => ['path' => '/wp-login.php']], 3600);
        $storage->set('203.0.113.9', ['request' => ['path' => '/xmlrpc.php']], 0);
        $storage->set('198.51.100.20', ['request' => ['path' => '/']], 7200);
        $storage->recordOffense('203.0.113.5');
        $storage->recordOffense('203.0.113.5');

        return $storage;
    }

    /**
     * Everything in force, across both address families.
     *
     * `find()` takes a pattern and offers no "everything" mode, so listing is
     * `0.0.0.0/0` and `::/0` — two questions, deliberately, because a single
     * pattern that could mean everything is one typo from deleting everything.
     */
    public function testListingReturnsEveryBlock(): void
    {
        $this->seed();

        $all = (new BlockList([$this->fileConfig()]))->all();

        $this->assertCount(3, $all);
        $this->assertArrayHasKey('203.0.113.5', $all);
        $this->assertArrayHasKey('198.51.100.20', $all);
    }

    /**
     * IPv6 blocks are listed too.
     */
    public function testListingIncludesIpv6(): void
    {
        $storage = $this->seed();
        $storage->set('2001:db8::1', ['request' => ['path' => '/']], 3600);

        $this->assertArrayHasKey('2001:db8::1', (new BlockList([$this->fileConfig()]))->all());
    }

    /**
     * A range matches what is inside it and nothing else.
     */
    public function testFindMatchesARange(): void
    {
        $this->seed();

        $found = (new BlockList([$this->fileConfig()]))->find('203.0.113.0/24');

        $this->assertSame(['203.0.113.5', '203.0.113.9'], array_keys($found));
    }

    /**
     * A malformed pattern matches nothing, never everything.
     *
     * The caller's next move is usually to delete what came back.
     */
    public function testAMalformedPatternMatchesNothing(): void
    {
        $this->seed();

        $this->assertSame([], (new BlockList([$this->fileConfig()]))->find('not-an-address'));
    }

    /**
     * Lifting removes the matching records and reports how many.
     */
    public function testLiftingRemovesAndCounts(): void
    {
        $this->seed();
        $blockList = new BlockList([$this->fileConfig()]);

        $this->assertSame(1, $blockList->lift(['203.0.113.5']));
        $this->assertSame([], $blockList->find('203.0.113.5'));
        $this->assertCount(2, $blockList->all(), 'The others are untouched');
    }

    /**
     * Lifting a range takes everything in it.
     */
    public function testLiftingARange(): void
    {
        $this->seed();
        $blockList = new BlockList([$this->fileConfig()]);

        $this->assertSame(2, $blockList->lift(['203.0.113.0/24']));
        $this->assertSame(['198.51.100.20'], array_keys($blockList->all()));
    }

    /**
     * Lifting nothing is not an error.
     *
     * A block that had already lapsed is a block nobody needs lifted, and an
     * operator clearing an address twice should not see a failure.
     */
    public function testLiftingSomethingUnblockedReportsZero(): void
    {
        $this->seed();

        $this->assertSame(0, (new BlockList([$this->fileConfig()]))->lift(['192.0.2.1']));
    }

    /**
     * One bad pattern does not cost the good ones.
     *
     * A typo in one of twenty ranges should still lift the other nineteen.
     */
    public function testABadPatternDoesNotAbortTheRest(): void
    {
        $this->seed();

        $this->assertSame(
            1,
            (new BlockList([$this->fileConfig()]))->lift(['nonsense', '203.0.113.5'])
        );
    }

    /**
     * Offence timestamps come back for an address.
     */
    public function testOffensesAreListed(): void
    {
        $this->seed();

        $offenses = (new BlockList([$this->fileConfig()]))->offenses('203.0.113.5');

        $this->assertNotSame([], $offenses);
        $this->assertContainsOnly('int', $offenses);
    }

    /**
     * The backend is named, and says whether it can answer at all.
     */
    public function testTheBackendDescribesItself(): void
    {
        $backend = (new BlockList([$this->fileConfig()]))->backend();

        $this->assertSame(FileStorage::class, $backend['class']);
        $this->assertTrue($backend['queryable']);
        $this->assertTrue($backend['durable'], 'A file outlives the process');
    }

    /**
     * A store that dies with the process says so.
     *
     * Every answer it gives is truthfully empty and completely misleading: an
     * operator would read "not blocked" and conclude the customer is fine,
     * when the truth is that this process never saw the site's block list.
     */
    public function testAnInMemoryStoreIsReportedAsNotDurable(): void
    {
        $config = $this->fileConfig();
        $config['storage'] = ['type' => InMemoryStorage::class];

        $backend = (new BlockList([$config]))->backend();

        $this->assertFalse($backend['durable']);
        $this->assertTrue($backend['queryable'], 'It can still enumerate — it just has nothing to enumerate');
    }

    /**
     * FileStorage extends InMemoryStorage and is still durable.
     *
     * Which is why the check is on the exact class rather than `instanceof` —
     * getting that wrong would warn on the most common backend there is.
     */
    public function testFileStorageIsNotMistakenForAnInMemoryOne(): void
    {
        $this->assertTrue((new BlockList([$this->fileConfig()]))->backend()['durable']);
    }

    /**
     * A backend that cannot enumerate answers nothing rather than fataling.
     *
     * Enumeration is modelled as a capability precisely because not every store
     * has it — the Memcached example in the custom-storage guide cannot list
     * keys at all.
     */
    public function testANonQueryableBackendAnswersEmpty(): void
    {
        $config = $this->fileConfig();
        $config['storage'] = ['type' => NonQueryableStorage::class];

        $blockList = new BlockList([$config]);

        $this->assertFalse($blockList->backend()['queryable']);
        $this->assertSame([], $blockList->all());
        $this->assertSame([], $blockList->find('203.0.113.5'));
        $this->assertSame(0, $blockList->lift(['203.0.113.5']));
        $this->assertSame([], $blockList->offenses('203.0.113.5'));
    }

    /**
     * The storage is built once, not per question.
     */
    public function testTheStorageIsBuiltOnce(): void
    {
        $blockList = new BlockList([$this->fileConfig()]);

        $this->assertSame($blockList->storage(), $blockList->storage());
    }
}
