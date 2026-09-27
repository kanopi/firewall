<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\BestEffortEnumerationInterface;
use Kanopi\Firewall\Storage\MemcachedStorage;
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Storage\FakeMemcached;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;
use Memcached;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;

/**
 * The Memcached block list, against an in-process Memcached (#392).
 *
 * `FakeMemcached` keeps state the way the server does, CAS tokens included, so the index can
 * be exercised through the moments a real server will not produce on request: a concurrent
 * writer between a read and a swap, a shard evicted between two writes, a failure on one
 * particular call. `MemcachedStorageIntegrationTest` covers the same backend against a real
 * server.
 *
 * Needs `ext-memcached` only because the fake extends `\Memcached`; nothing here opens a
 * connection except the tests about connecting.
 */
#[RequiresPhpExtension('memcached')]
final class MemcachedStorageTest extends AbstractTestCase
{
    private FakeMemcached $memcached;

    protected function setUp(): void
    {
        parent::setUp();

        LoggingFactory::setLogger(LoggingFactory::create([
            ['class' => TestLogHandler::class],
        ]));

        DegradedBackends::reset();
        $this->memcached = new FakeMemcached();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    private function storage(array $config = []): MemcachedStorage
    {
        return new MemcachedStorage(array_merge(['instance' => $this->memcached], $config));
    }

    private function logged(): TestLogHandler
    {
        $handler = LoggingFactory::logger()->getHandlers()[0] ?? null;
        $this->assertInstanceOf(TestLogHandler::class, $handler);

        return $handler;
    }

    /**
     * The raw JSON document at a key.
     *
     * @return array<string, mixed>
     */
    private function document(string $key): array
    {
        $this->assertArrayHasKey($key, $this->memcached->items, $key . ' is not stored');

        return json_decode((string) $this->memcached->items[$key]['value'], true, 512, JSON_THROW_ON_ERROR);
    }

    private function shardKeyFor(string $key): string
    {
        return 'firewall:index:' . (crc32($key) % MemcachedStorage::INDEX_SHARDS);
    }

    /**
     * An address in the same index shard as another, found by search.
     */
    private function sameShardAs(string $address): string
    {
        $shard = crc32($address) % MemcachedStorage::INDEX_SHARDS;

        for ($i = 1; $i < 65536; $i++) {
            $candidate = sprintf('10.99.%d.%d', intdiv($i, 256), $i % 256);

            if ($candidate !== $address && crc32($candidate) % MemcachedStorage::INDEX_SHARDS === $shard) {
                return $candidate;
            }
        }

        $this->fail('No address shares a shard with ' . $address);
    }

    // -----------------------------------------------------------------------
    // Capability and connection
    // -----------------------------------------------------------------------

    public function testItAdvertisesEnumerationAndItsLimits(): void
    {
        $storage = $this->storage();

        $this->assertInstanceOf(QueryableStorageInterface::class, $storage);
        $this->assertInstanceOf(BestEffortEnumerationInterface::class, $storage);
        $this->assertSame([], DegradedBackends::all());
    }

    /**
     * A server that does not answer degrades, and every method is safe afterwards.
     *
     * The same posture as RedisStorage: a block list that cannot be reached is reported,
     * and the firewall carries on enforcing everything that does not depend on it.
     */
    public function testAServerThatDoesNotAnswerDegradesEveryMethod(): void
    {
        $this->memcached->failNext('get', Memcached::RES_CONNECTION_FAILURE);

        $storage = $this->storage();

        $degraded = DegradedBackends::all();
        $this->assertCount(1, $degraded);
        $this->assertSame('block list', $degraded[0]['component']);
        $this->assertStringContainsString('no Memcached server answered', $degraded[0]['error']);

        $this->assertFalse($storage->set('203.0.113.5', ['a' => 1], 60));
        $this->assertSame('fallback', $storage->get('203.0.113.5', 'fallback'));
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertFalse($storage->delete('203.0.113.5'));
        $this->assertFalse($storage->addToExpire('203.0.113.5', 60));
        $this->assertFalse($storage->reset());
        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertSame([], $storage->listOffenses('203.0.113.5'));
        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertSame(0, $storage->deleteMatching(['203.0.113.0/24']));
        $this->assertTrue($storage->expire());

        // And says so, because every answer above is empty and "nothing is
        // blocked" is the one conclusion that must not be drawn from it.
        $this->assertStringContainsString('could be reached', (string) $storage->enumerationGap());
    }

    /**
     * One server of several failing does not take the block list with it.
     *
     * The probe is retried once per configured server, so a failed one can be ejected
     * and the next read routed to a live one.
     */
    public function testTheProbeIsRetriedOncePerServer(): void
    {
        $this->memcached->servers = [['host' => 'a', 'port' => 1], ['host' => 'b', 'port' => 1]];
        $this->memcached->failNext('get', Memcached::RES_CONNECTION_FAILURE);

        $this->storage();

        $this->assertSame([], DegradedBackends::all());
        $this->assertSame(2, $this->memcached->calls['get']);
    }

    /**
     * A client with no servers answers every read "not found", which is a block list that
     * is silently empty. It is refused instead.
     */
    public function testAConfigurationNamingNoUsableServerIsRefused(): void
    {
        $storage = new MemcachedStorage(['memcached' => ['servers' => [':11211', 42, ['port' => 11211]]]]);

        $degraded = DegradedBackends::all();
        $this->assertCount(1, $degraded);
        $this->assertStringContainsString('no usable Memcached server is configured', $degraded[0]['error']);
        $this->assertTrue($this->logged()->hasWarningContaining('Memcached server entry skipped'));
        $this->assertNotNull($storage->enumerationGap());
    }

    /**
     * Every documented way of naming a server reaches the client.
     *
     * Nothing is listening on the port, so the storage degrades -- the assertion is on
     * what it was pointed at, not on whether it connected.
     */
    public function testServersAreReadInEveryDocumentedForm(): void
    {
        $storage = new MemcachedStorage(['memcached' => [
            'servers' => ['127.0.0.1:1', '127.0.0.2', ['host' => '[::1]', 'port' => '2'], ['host' => '127.0.0.3', 'port' => 'x']],
            'connectTimeout' => 0.2,
            'readTimeout' => 'soon',
        ]]);

        $client = (new \ReflectionProperty(MemcachedStorage::class, 'memcached'))->getValue($storage);
        $this->assertNull($client, 'Nothing listens on these ports');

        // Built directly, so the list can be read back off the client.
        $connect = new \ReflectionMethod(MemcachedStorage::class, 'connect');
        $built = $connect->invoke($storage, [
            'servers' => ['127.0.0.1:1', '127.0.0.2', ['host' => '[::1]', 'port' => '2'], ['host' => '127.0.0.3', 'port' => 'x']],
        ]);

        $this->assertInstanceOf(Memcached::class, $built);
        $this->assertSame(
            [['127.0.0.1', 1], ['127.0.0.2', 11211], ['::1', 2], ['127.0.0.3', 11211]],
            array_map(static fn (array $server): array => [$server['host'], $server['port']], $built->getServerList())
        );
    }

    public function testASingleHostAndPortAreTheDefault(): void
    {
        $connect = new \ReflectionMethod(MemcachedStorage::class, 'connect');
        $built = $connect->invoke($this->storage(), []);

        $this->assertSame('127.0.0.1', $built->getServerList()[0]['host']);
        $this->assertSame(11211, $built->getServerList()[0]['port']);
    }

    /**
     * Timeouts are bounded, in the units each libmemcached option expects.
     */
    public function testTimeoutsAreBoundedAndConverted(): void
    {
        $connect = new \ReflectionMethod(MemcachedStorage::class, 'connect');

        $defaults = $connect->invoke($this->storage(), []);
        $this->assertSame(1500, $defaults->getOption(Memcached::OPT_CONNECT_TIMEOUT));
        $this->assertSame(1500, $defaults->getOption(Memcached::OPT_POLL_TIMEOUT));

        $configured = $connect->invoke($this->storage(), ['connectTimeout' => 5, 'readTimeout' => '0.25']);
        $this->assertSame(5000, $configured->getOption(Memcached::OPT_CONNECT_TIMEOUT));
        $this->assertSame(250, $configured->getOption(Memcached::OPT_POLL_TIMEOUT));
        $this->assertSame(250000, $configured->getOption(Memcached::OPT_RECV_TIMEOUT));
        $this->assertTrue((bool) $configured->getOption(Memcached::OPT_REMOVE_FAILED_SERVERS));
    }

    /**
     * SASL is only spoken over the binary protocol, so naming a user switches to it.
     */
    public function testAUsernameSwitchesToTheBinaryProtocol(): void
    {
        $connect = new \ReflectionMethod(MemcachedStorage::class, 'connect');

        $plain = $connect->invoke($this->storage(), []);
        $this->assertFalse((bool) $plain->getOption(Memcached::OPT_BINARY_PROTOCOL));

        $authenticated = $connect->invoke($this->storage(), ['username' => 'firewall', 'password' => 'secret']);
        $this->assertTrue((bool) $authenticated->getOption(Memcached::OPT_BINARY_PROTOCOL));
    }

    // -----------------------------------------------------------------------
    // Records
    // -----------------------------------------------------------------------

    public function testABlockRoundTripsWithItsExpiry(): void
    {
        $storage = $this->storage();

        $this->assertTrue($storage->set('203.0.113.5', ['reason' => 'test'], 300));

        $this->assertSame(['reason' => 'test'], $storage->get('203.0.113.5'));
        $this->assertTrue($storage->exists('203.0.113.5'));
        $this->assertSame(['reason' => 'test'], $storage->isBlocked('203.0.113.5'));

        $record = $this->document('firewall:block:203.0.113.5');
        $this->assertEqualsWithDelta(time() + 300, $record['e'], 2);
        $this->assertEqualsWithDelta(time() + 300, $this->memcached->items['firewall:block:203.0.113.5']['expires'], 2);
    }

    public function testAPermanentBlockHasNoExpiry(): void
    {
        $this->storage()->set('203.0.113.5', ['reason' => 'forever'], 0);

        $this->assertSame(0, $this->document('firewall:block:203.0.113.5')['e']);
        $this->assertSame(0, $this->memcached->items['firewall:block:203.0.113.5']['expires']);
    }

    /**
     * Memcached reads an expiry over 30 days as a unix timestamp.
     *
     * A ninety-day ban passed through as seconds would be read as a moment in 1970 and
     * vanish as it was written.
     */
    public function testABanLongerThanThirtyDaysIsGivenAnAbsoluteExpiry(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['reason' => 'long'], 90 * 86400);

        $this->assertEqualsWithDelta(time() + 90 * 86400, $this->memcached->items['firewall:block:203.0.113.5']['expires'], 2);
        $this->assertSame(['reason' => 'long'], $storage->get('203.0.113.5'));
    }

    public function testWritingABlockRecordsAnOffense(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 60);

        $this->assertSame(1, $storage->countOffenses('203.0.113.5'));
    }

    public function testAnUnencodableValueIsRefused(): void
    {
        $storage = $this->storage();

        $this->assertFalse($storage->set('203.0.113.5', ['bad' => "\xB1\x31"], 60));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to encode value'));
        $this->assertArrayNotHasKey('firewall:block:203.0.113.5', $this->memcached->items);
    }

    public function testAFailedWriteIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('set');

        $this->assertFalse($storage->set('203.0.113.5', ['a' => 1], 60));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to write to Memcached storage'));
    }

    public function testAnAbsentKeyReturnsTheDefault(): void
    {
        $this->assertSame('fallback', $this->storage()->get('nobody', 'fallback'));
        $this->assertFalse($this->logged()->hasErrorContaining('Failed to read'));
    }

    /**
     * A read that failed is not the same fact as nothing stored, and is logged as such.
     */
    public function testAFailedReadIsReportedRatherThanAnsweredQuietly(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('get');

        $this->assertNull($storage->get('203.0.113.5'));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to read from Memcached storage'));
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function provideUndecodableValues(): array
    {
        return [
            'broken json' => ['{"broken'],
            'not a record' => ['"just a string"'],
            'no expiry field' => ['{"v":{"a":1}}'],
            'not a string at all' => [42],
        ];
    }

    /**
     * For a block list, quietly answering the default reads as "not blocked".
     */
    #[DataProvider('provideUndecodableValues')]
    public function testAnUndecodableRecordIsReported(mixed $raw): void
    {
        $storage = $this->storage();
        $this->memcached->put('firewall:block:203.0.113.5', $raw);

        $this->assertNull($storage->get('203.0.113.5'));
        $this->assertTrue($this->logged()->hasErrorContaining('could not be decoded'));
    }

    /**
     * A server whose clock runs behind this host's has not yet dropped a lapsed ban.
     */
    public function testALapsedRecordIsNotInForce(): void
    {
        $storage = $this->storage();
        $this->memcached->put('firewall:block:203.0.113.5', json_encode(['v' => ['a' => 1], 'e' => time() - 5]));

        $this->assertFalse($storage->exists('203.0.113.5'));
    }

    public function testDeletingARecord(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 60);

        $this->assertTrue($storage->delete('203.0.113.5'));
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertArrayNotHasKey('203.0.113.5', $this->document($this->shardKeyFor('203.0.113.5'))['k']);

        $this->assertFalse($storage->delete('203.0.113.5'), 'Nothing left to delete');
        $this->assertFalse($this->logged()->hasErrorContaining('Failed to delete'));
    }

    public function testAFailedDeleteIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('delete');

        $this->assertFalse($storage->delete('203.0.113.5'));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to delete from Memcached storage'));
    }

    /**
     * An address never needs it, but `set()` is a general key/value write, and Memcached
     * refuses keys over 250 bytes or containing whitespace.
     *
     * @return array<string, array{0: string}>
     */
    public static function provideKeysMemcachedWouldRefuse(): array
    {
        return [
            'too long' => ['fw_challenge_revoked:' . str_repeat('a', 300)],
            'whitespace' => ['a key with spaces'],
            'control character' => ["tab\tkey"],
        ];
    }

    #[DataProvider('provideKeysMemcachedWouldRefuse')]
    public function testAKeyMemcachedWouldRefuseIsHashed(string $key): void
    {
        $storage = $this->storage();

        $this->assertTrue($storage->set($key, ['consumed_at' => 123], 60));
        $this->assertSame(['consumed_at' => 123], $storage->get($key));

        foreach (array_keys($this->memcached->items) as $item) {
            $this->assertLessThanOrEqual(250, strlen($item));
            $this->assertDoesNotMatchRegularExpression('/\s/', $item);
        }
    }

    public function testExpireIsANoOp(): void
    {
        $this->assertTrue($this->storage()->expire());
    }

    // -----------------------------------------------------------------------
    // addToExpire()
    // -----------------------------------------------------------------------

    /**
     * Memcached cannot report the time an item has left, so it is read off the record.
     */
    public function testExtendingABanAddsToWhatIsLeft(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 300);
        $before = $this->document('firewall:block:203.0.113.5')['e'];

        $this->assertTrue($storage->addToExpire('203.0.113.5', 600));

        $this->assertSame($before + 600, $this->document('firewall:block:203.0.113.5')['e']);
        $this->assertEqualsWithDelta(time() + 900, $this->memcached->items['firewall:block:203.0.113.5']['expires'], 2);

        // And the index, which prunes by expiry: left stale, the entry would be
        // dropped while the block it points at was still in force.
        $this->assertSame($before + 600, $this->document($this->shardKeyFor('203.0.113.5'))['k']['203.0.113.5']);
    }

    public function testExtendingAPermanentOrMissingBanDoesNothing(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 0);

        $this->assertFalse($storage->addToExpire('203.0.113.5', 600));
        $this->assertFalse($storage->addToExpire('198.51.100.7', 600));
        $this->assertSame(0, $this->document('firewall:block:203.0.113.5')['e']);
    }

    public function testAFailedExtensionIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('get');

        $this->assertFalse($storage->addToExpire('203.0.113.5', 600));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to extend expiry'));
    }

    // -----------------------------------------------------------------------
    // Offenses
    // -----------------------------------------------------------------------

    public function testOffensesAreCountedAndListedWithinAWindow(): void
    {
        $storage = $this->storage();
        $now = time();
        $this->memcached->put('firewall:offense:203.0.113.5', json_encode(['t' => [$now - 300, $now - 200, $now - 100]]));

        $this->assertSame(3, $storage->countOffenses('203.0.113.5'));
        $this->assertSame(2, $storage->countOffenses('203.0.113.5', $now - 250));
        $this->assertSame([$now - 100, $now - 200, $now - 300], $storage->listOffenses('203.0.113.5'));
        $this->assertSame([$now - 100], $storage->listOffenses('203.0.113.5', 0, PHP_INT_MAX, 1));
        $this->assertCount(3, $storage->listOffenses('203.0.113.5', 0, PHP_INT_MAX, 0), 'A limit of zero is no limit');
        $this->assertSame([$now - 200], $storage->listOffenses('203.0.113.5', $now - 250, $now - 150));
    }

    /**
     * Two offenses in the same second both count.
     */
    public function testOffensesInOneSecondAreCountedSeparately(): void
    {
        $storage = $this->storage();

        $storage->recordOffense('203.0.113.5');
        $storage->recordOffense('203.0.113.5');

        $this->assertSame(2, $storage->countOffenses('203.0.113.5'));
    }

    /**
     * An offense list is one item, and an item has a size limit.
     */
    public function testOffenseHistoryIsCappedAtTheMostRecent(): void
    {
        $storage = $this->storage();
        $this->memcached->put('firewall:offense:203.0.113.5', json_encode(['t' => range(1, MemcachedStorage::MAX_OFFENSES)]));

        $this->assertTrue($storage->recordOffense('203.0.113.5'));

        $moments = $this->document('firewall:offense:203.0.113.5')['t'];
        $this->assertCount(MemcachedStorage::MAX_OFFENSES, $moments);
        $this->assertSame(2, $moments[0], 'The oldest is the one dropped');
        $this->assertSame(time(), end($moments));
    }

    public function testAFailedOffenseWriteIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('get');

        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to record offense'));
    }

    /**
     * A count that could not be taken is not the same fact as a count of none (#181).
     */
    public function testAFailedOffenseReadIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('get');

        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to read offenses'));
    }

    public function testAnUnreadableOffenseListCountsAsNone(): void
    {
        $storage = $this->storage();
        $this->memcached->put('firewall:offense:203.0.113.5', '{"t":"not a list"}');

        $this->assertSame([], $storage->listOffenses('203.0.113.5'));
    }

    // -----------------------------------------------------------------------
    // Compare-and-swap
    // -----------------------------------------------------------------------

    /**
     * The whole reason for compare-and-swap: two workers writing one shard.
     *
     * Without it, each would write back its own copy and one block would disappear from
     * the index while still being enforced.
     */
    public function testAConcurrentWriterBetweenReadAndSwapIsNotOverwritten(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 60);

        $neighbour = $this->sameShardAs('203.0.113.5');
        $shardKey = $this->shardKeyFor('203.0.113.5');
        $interrupted = false;

        $this->memcached->beforeCas = function (string $key, FakeMemcached $memcached) use ($shardKey, &$interrupted): void {
            if ($key !== $shardKey || $interrupted) {
                return;
            }

            // Another worker indexes a block of its own, first.
            $interrupted = true;
            $document = json_decode((string) $memcached->items[$key]['value'], true);
            $document['k']['192.0.2.200'] = 0;
            $memcached->put($key, json_encode($document));
        };

        $storage->set($neighbour, ['b' => 2], 60);

        $entries = $this->document($shardKey)['k'];
        $this->assertTrue($interrupted);
        $this->assertArrayHasKey('203.0.113.5', $entries);
        $this->assertArrayHasKey($neighbour, $entries);
        $this->assertArrayHasKey('192.0.2.200', $entries, 'The concurrent write survived');
    }

    /**
     * Two workers creating the same item: `add` fails for the second, which then swaps.
     */
    public function testLosingTheRaceToCreateAnItemRetriesAsASwap(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('add', Memcached::RES_NOTSTORED);

        $this->assertTrue($storage->recordOffense('203.0.113.5'));
        $this->assertSame(1, $storage->countOffenses('203.0.113.5'));
    }

    /**
     * Contention is bounded. A shard rewritten under every attempt gives up, and says so
     * both in the log and to a status page -- the block is still enforced, only a range
     * search would miss it.
     */
    public function testAnIndexWriteThatNeverWinsTheRaceIsReported(): void
    {
        $storage = $this->storage();
        $storage->set('198.51.100.1', ['a' => 1], 60);
        $shardKey = $this->shardKeyFor('203.0.113.5');

        $this->memcached->beforeCas = static function (string $key, FakeMemcached $memcached) use ($shardKey): void {
            if ($key === $shardKey) {
                $memcached->put($key, $memcached->items[$key]['value']);
            }
        };

        $this->assertTrue($storage->set('203.0.113.5', ['a' => 1], 60), 'The block itself is written');
        $this->assertTrue($storage->exists('203.0.113.5'));

        $this->assertTrue($this->logged()->hasErrorContaining('the block is enforced but a range search will not find it'));
        $degraded = DegradedBackends::all();
        $this->assertCount(1, $degraded);
        $this->assertSame('block list index', $degraded[0]['component']);
        $this->assertStringContainsString('rewritten by another worker', $degraded[0]['error']);
    }

    public function testAnOffenseThatNeverWinsTheRaceIsReported(): void
    {
        $storage = $this->storage();
        $storage->recordOffense('203.0.113.5');

        $this->memcached->beforeCas = static function (string $key, FakeMemcached $memcached): void {
            $memcached->put($key, $memcached->items[$key]['value']);
        };

        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertTrue($this->logged()->hasWarningContaining('too much contention'));
    }

    /**
     * A swap that fails for any reason other than contention is a failure, not a retry.
     */
    public function testAServerFailureDuringASwapIsNotRetried(): void
    {
        $storage = $this->storage();
        $storage->recordOffense('203.0.113.5');
        $this->memcached->failNext('cas', Memcached::RES_SERVER_ERROR);

        $this->assertFalse($storage->recordOffense('203.0.113.5'));
        $this->assertSame(1, $this->memcached->calls['cas']);
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to record offense'));
    }

    public function testAFailedIndexReadIsReportedAndTheBlockStillWritten(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('getMulti');

        $this->assertTrue($storage->set('203.0.113.5', ['a' => 1], 60));
        $this->assertSame('block list index', DegradedBackends::all()[0]['component']);
    }

    // -----------------------------------------------------------------------
    // find()
    // -----------------------------------------------------------------------

    private function seed(MemcachedStorage $storage): void
    {
        foreach (['203.0.113.5', '203.0.113.99', '198.51.100.7', '2001:db8::1', '8.8.8.8'] as $address) {
            $storage->set($address, ['event_id' => 'evt-' . $address], 600);
        }

        // Not an address: stored, indexed, and never matched by one.
        $storage->set('fw_challenge_revoked:abc', ['consumed_at' => 1], 600);
    }

    public function testFindByRange(): void
    {
        $storage = $this->storage();
        $this->seed($storage);

        $found = $storage->find('203.0.113.0/24');

        $this->assertSame(['203.0.113.5', '203.0.113.99'], $this->sorted(array_keys($found)));
        $this->assertSame(['event_id' => 'evt-203.0.113.5'], $found['203.0.113.5']['value']);
        $this->assertEqualsWithDelta(time() + 600, $found['203.0.113.5']['expire'], 2);
        $this->assertSame(date('c', $found['203.0.113.5']['expire']), $found['203.0.113.5']['expires_at']);
        $this->assertSame(1, $found['203.0.113.5']['offenses']);
    }

    public function testFindEverything(): void
    {
        $storage = $this->storage();
        $this->seed($storage);

        $this->assertCount(4, $storage->find('0.0.0.0/0'));
        $this->assertSame(['2001:db8::1'], array_keys($storage->find('::/0')));
    }

    /**
     * A single address is looked up directly and never touches the index.
     */
    public function testFindByExactAddressDoesNotReadTheIndex(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 0);
        $before = $this->memcached->calls['getMulti'] ?? 0;

        $found = $storage->find('203.0.113.5');

        $this->assertSame(['203.0.113.5'], array_keys($found));
        $this->assertSame(0, $found['203.0.113.5']['expire']);
        $this->assertNull($found['203.0.113.5']['expires_at']);
        $this->assertSame($before + 1, $this->memcached->calls['getMulti'], 'One read for the record and its offenses, none for the index');
        $this->assertSame([], $storage->find('198.51.100.7'));
    }

    public function testFindExcludesLapsedEntries(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);

        // The index still lists it; the record is gone, as Memcached would drop it.
        $shardKey = $this->shardKeyFor('203.0.113.9');
        $document = $this->document($shardKey);
        $document['k']['203.0.113.9'] = time() - 10;
        $this->memcached->put($shardKey, json_encode($document));

        $this->assertSame(['203.0.113.5'], array_keys($storage->find('203.0.113.0/24')));
    }

    /**
     * An index entry pointing at nothing -- evicted, or deleted since -- is skipped, as is
     * one pointing at a record that cannot be read.
     */
    public function testFindSkipsEntriesWithNoReadableRecord(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $storage->set('203.0.113.6', ['a' => 1], 600);
        $storage->set('203.0.113.7', ['a' => 1], 600);

        $this->memcached->evict('firewall:block:203.0.113.6');
        $this->memcached->put('firewall:block:203.0.113.7', '{"broken');

        $this->assertSame(['203.0.113.5'], array_keys($storage->find('203.0.113.0/24')));
    }

    public function testAnInvalidPatternIsRefused(): void
    {
        $storage = $this->storage();

        $this->assertSame([], $storage->find('203.0.113.0/33'));
        $this->assertTrue($this->logged()->hasWarningContaining('not a valid address or CIDR range'));
    }

    public function testAFailedSearchIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('getMulti');

        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to search Memcached storage'));
    }

    public function testASearchOverAGapIsLogged(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));

        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertTrue($this->logged()->hasWarningContaining('search may be incomplete'));

        // The exact address is still found, which is the point of looking it up directly.
        $this->assertSame(['203.0.113.5'], array_keys($storage->find('203.0.113.5')));
    }

    /**
     * @param array<int, string> $values
     *
     * @return array<int, string>
     */
    private function sorted(array $values): array
    {
        sort($values);

        return $values;
    }

    // -----------------------------------------------------------------------
    // deleteMatching()
    // -----------------------------------------------------------------------

    public function testDeleteMatchingByRangeRemovesBlocksAndOffenses(): void
    {
        $storage = $this->storage();
        $this->seed($storage);

        $this->assertSame(2, $storage->deleteMatching(['203.0.113.0/24']));

        $this->assertSame([], $storage->find('203.0.113.0/24'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertTrue($storage->exists('198.51.100.7'));
        $this->assertArrayNotHasKey('203.0.113.5', $this->document($this->shardKeyFor('203.0.113.5'))['k']);
    }

    public function testOverlappingPatternsCountEachRecordOnce(): void
    {
        $storage = $this->storage();
        $this->seed($storage);

        $this->assertSame(2, $storage->deleteMatching(['203.0.113.0/24', '203.0.113.5', '203.0.113.0/25']));
    }

    /**
     * An exact un-block works for a block the index has lost.
     */
    public function testAnExactAddressIsDeletedEvenWhenTheIndexHasLostIt(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));
        $before = $this->memcached->calls['getMulti'] ?? 0;

        $this->assertSame(1, $storage->deleteMatching(['203.0.113.5']));
        $this->assertFalse($storage->exists('203.0.113.5'));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
        $this->assertSame($before + 1, $this->memcached->calls['getMulti'], 'One read to rewrite its own shard; none of the whole index');
    }

    /**
     * An address that was never blocked keeps its offense history: lifting a block that
     * does not exist should not quietly reset escalation.
     */
    public function testAnExactAddressThatWasNotBlockedKeepsItsHistory(): void
    {
        $storage = $this->storage();
        $storage->recordOffense('203.0.113.5');

        $this->assertSame(0, $storage->deleteMatching(['203.0.113.5']));
        $this->assertSame(1, $storage->countOffenses('203.0.113.5'));
    }

    /**
     * A lapsed block's record is already gone, but its offense history is not, and an
     * operator lifting the range expects it to go too.
     */
    public function testALapsedEntryInTheRangeHasItsHistoryCleared(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->evict('firewall:block:203.0.113.5');

        $this->assertSame(0, $storage->deleteMatching(['203.0.113.0/24']));
        $this->assertSame(0, $storage->countOffenses('203.0.113.5'));
    }

    public function testARangeMatchingNothingDeletesNothing(): void
    {
        $storage = $this->storage();
        $this->seed($storage);
        $deletes = $this->memcached->calls['deleteMulti'] ?? 0;

        $this->assertSame(0, $storage->deleteMatching(['192.0.2.0/24']));
        $this->assertSame($deletes, $this->memcached->calls['deleteMulti'] ?? 0);
        $this->assertCount(4, $storage->find('0.0.0.0/0'));
    }

    public function testNoValidPatternTouchesNothing(): void
    {
        $storage = $this->storage();
        $this->seed($storage);

        $this->assertSame(0, $storage->deleteMatching(['nonsense', 42]));
        $this->assertCount(4, $storage->find('0.0.0.0/0'));
    }

    public function testAFailedRangeDeleteIsReported(): void
    {
        $storage = $this->storage();
        $this->seed($storage);
        $this->memcached->failNext('getMulti');

        $this->assertSame(0, $storage->deleteMatching(['203.0.113.0/24']));
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to delete matching records'));
    }

    // -----------------------------------------------------------------------
    // reset()
    // -----------------------------------------------------------------------

    /**
     * Only this backend's keys go. `flush()` would clear every application on the server.
     */
    public function testResetClearsWhatTheIndexKnowsAndLeavesNeighboursAlone(): void
    {
        $storage = $this->storage();
        $this->seed($storage);
        $this->memcached->put('someone-else:session', 'theirs');

        $this->assertTrue($storage->reset());

        $this->assertSame(['someone-else:session'], array_keys($this->memcached->items));
        $this->assertNull($storage->get('fw_challenge_revoked:abc'));
        $this->assertNull($storage->enumerationGap());
    }

    public function testAFailedResetIsReported(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('getMulti');

        $this->assertFalse($storage->reset());
        $this->assertTrue($this->logged()->hasErrorContaining('Failed to reset Memcached storage'));
    }

    // -----------------------------------------------------------------------
    // The index, and its gaps
    // -----------------------------------------------------------------------

    public function testAFreshStoreHasNoGap(): void
    {
        $this->assertNull($this->storage()->enumerationGap());
    }

    public function testAnUnreadableIndexIsAGap(): void
    {
        $storage = $this->storage();
        $this->memcached->failNext('getMulti');

        $this->assertStringContainsString('could not be read', (string) $storage->enumerationGap());
    }

    /**
     * The first write starts every shard, so a shard that is missing later was lost rather
     * than never written.
     */
    public function testTheFirstWriteStartsEveryShard(): void
    {
        $this->storage()->set('203.0.113.5', ['a' => 1], 60);

        for ($shard = 0; $shard < MemcachedStorage::INDEX_SHARDS; $shard++) {
            $this->assertArrayHasKey('firewall:index:' . $shard, $this->memcached->items);
        }

        $this->assertArrayHasKey('firewall:index:meta', $this->memcached->items);
    }

    /**
     * Noticed on read, before any write has recorded it.
     */
    public function testAMissingShardIsAGapWhileAnythingItHeldCouldBeInForce(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);

        $this->memcached->evict('firewall:index:3');
        $this->assertStringContainsString('1 of 64 index shards is missing', (string) $storage->enumerationGap());

        $this->memcached->evict('firewall:index:4');
        $this->assertStringContainsString('2 of 64 index shards are missing', (string) $storage->enumerationGap());
    }

    /**
     * An index that has never held an entry cannot have lost one.
     */
    public function testAMissingShardFromAnEmptyIndexIsNoGap(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $storage->reset();
        $this->memcached->put('firewall:index:meta', json_encode(['started' => time(), 'horizon' => null, 'lost' => null]));

        $this->assertNull($storage->enumerationGap());
    }

    /**
     * Once a write notices the loss, it is recorded -- and reported until every block the
     * shard could have held has expired, which the horizon says.
     */
    public function testANoticedLossIsRecordedUntilTheHorizon(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $horizon = $this->document('firewall:index:meta')['horizon'];

        $this->assertSame(0, $horizon % 3600, 'Rounded to the hour, so a stream of bans does not rewrite it every time');
        $this->assertGreaterThanOrEqual(time() + 600, $horizon);

        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));
        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);

        $lost = $this->document('firewall:index:meta')['lost'];
        $this->assertSame($horizon, $lost['until']);
        $this->assertStringContainsString('until ' . date('Y-m-d H:i:s', $horizon), (string) $storage->enumerationGap());
        $this->assertTrue($this->logged()->hasWarningContaining('shard was evicted'));
    }

    /**
     * A permanent ban has no expiry, so a loss after one is reported until reset.
     */
    public function testALossAfterAPermanentBanIsReportedUntilReset(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 0);
        $this->assertSame(0, $this->document('firewall:index:meta')['horizon']);

        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));
        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);

        $this->assertStringContainsString('until the store is reset', (string) $storage->enumerationGap());
    }

    /**
     * Nothing indexed outlived the horizon, so whatever a shard held has lapsed anyway.
     */
    public function testALossAfterTheHorizonIsNoGap(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);

        $meta = $this->document('firewall:index:meta');
        $meta['horizon'] = time() - 10;
        $this->memcached->put('firewall:index:meta', json_encode($meta));

        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));
        $this->assertNull($storage->enumerationGap(), 'Missing, but nothing it held can still be in force');

        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);
        $this->assertNull($this->document('firewall:index:meta')['lost']);
    }

    /**
     * A second loss widens the window; "forever" wins over any date.
     */
    public function testASecondLossExtendsTheFirst(): void
    {
        $storage = $this->storage();
        $later = time() + 7200;
        $this->memcached->put('firewall:index:meta', json_encode([
            'started' => time(),
            'horizon' => $later,
            'lost' => ['since' => time() - 60, 'until' => time() + 60, 'what' => 'index shard 1'],
        ]));

        $shardLost = new \ReflectionMethod(MemcachedStorage::class, 'shardLost');
        $shardLost->invoke($storage, $this->document('firewall:index:meta'), 2);

        $lost = $this->document('firewall:index:meta')['lost'];
        $this->assertSame($later, $lost['until']);
        $this->assertSame(time() - 60, $lost['since'], 'The loss began when the first one did');

        $meta = $this->document('firewall:index:meta');
        $meta['horizon'] = 0;
        $this->memcached->put('firewall:index:meta', json_encode($meta));
        $shardLost->invoke($storage, $meta, 3);

        $this->assertSame(0, $this->document('firewall:index:meta')['lost']['until']);
    }

    /**
     * A loss that has healed does not stretch a new one back to its start.
     */
    public function testANewLossAfterAHealedOneStartsAfresh(): void
    {
        $storage = $this->storage();
        $meta = [
            'started' => time() - 86400,
            'horizon' => time() + 3600,
            'lost' => ['since' => time() - 86400, 'until' => time() - 60, 'what' => 'index shard 1'],
        ];
        $this->memcached->put('firewall:index:meta', json_encode($meta));

        for ($shard = 0; $shard < MemcachedStorage::INDEX_SHARDS; $shard++) {
            $this->memcached->put('firewall:index:' . $shard, '{"k":{}}');
        }

        $this->assertNull($storage->enumerationGap(), 'The first loss has healed');

        (new \ReflectionMethod(MemcachedStorage::class, 'shardLost'))->invoke($storage, $meta, 2);

        $lost = $this->document('firewall:index:meta')['lost'];
        $this->assertSame(time(), $lost['since']);
        $this->assertSame('index shard 2', $lost['what']);
    }

    /**
     * Shards without their meta key: an index that was here, and whose record of what it
     * held is gone. How far back the loss reaches cannot be known.
     */
    public function testShardsWithoutTheirMetaKeyAreAGapUntilReset(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->evict('firewall:index:meta');

        $this->assertStringContainsString('lost its meta key', (string) $storage->enumerationGap());

        // A write notices, and records it for good.
        $storage->set('198.51.100.7', ['a' => 1], 60);

        $this->assertSame(0, $this->document('firewall:index:meta')['lost']['until']);
        $this->assertStringContainsString('the index meta key', (string) $storage->enumerationGap());
        $this->assertTrue($this->logged()->hasWarningContaining('lost its meta key'));
    }

    /**
     * A shard that is there and cannot be read is as lost as one that is not there --
     * the next write would otherwise replace it with an empty one, silently.
     */
    public function testACorruptShardIsTreatedAsLost(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->put($this->shardKeyFor('203.0.113.5'), '{"broken');

        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);

        $this->assertNotNull($this->document('firewall:index:meta')['lost']);
    }

    /**
     * Two gaps at once are both reported.
     */
    public function testARecordedLossAndAnUnnoticedOneAreBothReported(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);
        $this->memcached->evict($this->shardKeyFor('203.0.113.5'));
        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);

        $other = ((crc32('203.0.113.5') % MemcachedStorage::INDEX_SHARDS) + 1) % MemcachedStorage::INDEX_SHARDS;
        $this->memcached->evict('firewall:index:' . $other);

        $gap = (string) $storage->enumerationGap();
        $this->assertStringContainsString('was evicted at', $gap);
        $this->assertStringContainsString('1 of 64 index shards is missing', $gap);
    }

    /**
     * The horizon only moves outward, and not at all once it is "forever".
     */
    public function testTheHorizonOnlyMovesOutward(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 7200);
        $far = $this->document('firewall:index:meta')['horizon'];

        $storage->set('203.0.113.6', ['a' => 1], 60);
        $this->assertSame($far, $this->document('firewall:index:meta')['horizon']);

        $storage->set('203.0.113.7', ['a' => 1], 0);
        $this->assertSame(0, $this->document('firewall:index:meta')['horizon']);

        $storage->set('203.0.113.8', ['a' => 1], 86400);
        $this->assertSame(0, $this->document('firewall:index:meta')['horizon']);
    }

    /**
     * Rechecked under the swap: another worker may have moved the horizon, or the meta key
     * may have gone, since it was read.
     */
    public function testTheHorizonIsRecheckedWhenItIsWritten(): void
    {
        $storage = $this->storage();
        $extend = new \ReflectionMethod(MemcachedStorage::class, 'extendHorizon');

        $extend->invoke($storage, time() + 60);
        $this->assertArrayNotHasKey('firewall:index:meta', $this->memcached->items, 'No meta key to extend');

        $covered = time() + 86400;
        $this->memcached->put('firewall:index:meta', json_encode(['started' => time(), 'horizon' => $covered, 'lost' => null]));
        $extend->invoke($storage, time() + 60);

        $this->assertSame($covered, $this->document('firewall:index:meta')['horizon']);
    }

    /**
     * An index entry that is not an expiry is dropped on the next write, not carried.
     */
    public function testMalformedIndexEntriesArePrunedOnWrite(): void
    {
        $storage = $this->storage();
        $storage->set('203.0.113.5', ['a' => 1], 600);

        $shardKey = $this->shardKeyFor('203.0.113.5');
        $document = $this->document($shardKey);
        $document['k']['junk'] = 'not a timestamp';
        $document['k']['203.0.113.250'] = time() - 5;
        $this->memcached->put($shardKey, json_encode($document));

        $storage->set($this->sameShardAs('203.0.113.5'), ['b' => 2], 60);

        $entries = $this->document($shardKey)['k'];
        $this->assertArrayNotHasKey('junk', $entries);
        $this->assertArrayNotHasKey('203.0.113.250', $entries);
        $this->assertArrayHasKey('203.0.113.5', $entries);
    }
}
