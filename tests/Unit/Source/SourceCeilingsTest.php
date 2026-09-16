<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\EntryValidator;
use Kanopi\Firewall\Source\Fetcher\HttpFetcher;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Source\SourceUpstream;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Bounding a source by size and entry count, not only by time (#366).
 *
 * `upstream.timeout` bounds how long a fetch may take and `max_redirects`
 * bounds where it may go. Nothing bounded how much came back, so an upstream
 * that grew without bound was read without bound — and a list that grows to
 * four gigabytes should fail, not take the refresh job with it.
 */
class SourceCeilingsTest extends AbstractTestCase
{
    private string $workspace;

    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-ceilings-' . bin2hex(random_bytes(6));
        mkdir($this->workspace . '/cache', 0775, true);
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->workspace . '/{,cache/}*', GLOB_BRACE) as $path) {
            if (is_string($path) && is_file($path)) {
                @unlink($path);
            }
        }

        @rmdir($this->workspace . '/cache');
        @rmdir($this->workspace);
        parent::tearDown();
    }

    /**
     * A finite ceiling with no configuration, so #120's "should fail, not OOM"
     * is true for a source nobody has tuned.
     */
    public function testThereIsACeilingWithoutAnybodyConfiguringOne(): void
    {
        $this->assertSame(
            SourceUpstream::DEFAULT_MAX_SIZE,
            SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt'])->upstream->maxSize
        );
    }

    /**
     * `10M` is what an operator types; `10485760` is what they would have had
     * to work out.
     */
    #[DataProvider('sizeProvider')]
    public function testASizeIsReadInTheUnitsPeopleWrite(mixed $declared, int $expected): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/list.txt', 'max_size' => $declared],
        ]);

        $this->assertSame($expected, $definition->upstream->maxSize);
    }

    /**
     * @return array<string, array{0: mixed, 1: int}>
     */
    public static function sizeProvider(): array
    {
        return [
            'bytes' => [2048, 2048],
            'kilobytes' => ['64K', 65536],
            'megabytes' => ['10M', 10485760],
            'gigabytes' => ['1G', 1073741824],
            'lowercase' => ['10m', 10485760],
            'with a b' => ['10MB', 10485760],
            'spaced' => [' 10 M ', 10485760],
            'a bare number as a string' => ['4096', 4096],
            'no limit' => [0, 0],
        ];
    }

    /**
     * Silently falling back to the default would leave an operator believing
     * they had set a ceiling they had not.
     */
    #[DataProvider('badSizeProvider')]
    public function testASizeThatCannotBeReadIsRefused(mixed $declared): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('upstream.max_size must be a number of bytes or a size such as "10M"');

        SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/list.txt', 'max_size' => $declared],
        ]);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function badSizeProvider(): array
    {
        return [
            'prose' => ['about ten megs'],
            'negative' => [-1],
            'a list' => [[10]],
            'a boolean' => [true],
            'a unit nobody uses' => ['10TB'],
        ];
    }

    /**
     * A local file is the one upstream whose size can be known without paying
     * for it, so this costs a stat rather than a four-gigabyte string.
     */
    public function testAnOversizedLocalFileIsRefusedWithoutBeingRead(): void
    {
        $path = $this->fixture('big.txt', str_repeat("10.0.0.1\n", 200));

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('more than upstream.max_size allows');

        $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => ['url' => $path, 'max_size' => 64],
        ]));
    }

    public function testALocalFileWithinTheCeilingLoadsNormally(): void
    {
        $path = $this->fixture('small.txt', "10.0.0.1\n10.0.0.2\n");

        $this->assertSame(
            ['10.0.0.1', '10.0.0.2'],
            $this->loader()->load(SourceDefinition::fromArray([
                'upstream' => ['url' => $path, 'max_size' => '1K'],
            ]))
        );
    }

    /**
     * `max_size: 0` is a deployment saying it means it.
     */
    public function testNoLimitMeansNoLimit(): void
    {
        $path = $this->fixture('unbounded.txt', str_repeat("10.0.0.1\n", 100));

        $this->assertNotSame([], $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => ['url' => $path, 'max_size' => 0],
        ])));
    }

    /**
     * Refused rather than truncated. Half a block list is a list whose meaning
     * nobody knows: it loads, matches fewer things than it should, and looks
     * exactly like a list that is simply shorter this week.
     */
    #[DataProvider('oversizedProvider')]
    public function testAnOversizedHttpBodyIsRefusedRatherThanTruncated(mixed $limit, string $described): void
    {
        // One byte past whatever the ceiling is, which is all the real reader
        // would have had in hand at the point it gave up.
        $fetcher = new class extends HttpFetcher {
            protected function readStream(SourceDefinition $sourceDefinition, string $url, array $options): array
            {
                return [str_repeat('x', $sourceDefinition->upstream->maxSize + 1), ['HTTP/1.1 200 OK']];
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('upstream sent more than upstream.max_size allows (' . $described . ')');

        $this->loader($fetcher)->load(SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/list.txt', 'max_size' => $limit],
        ]));
    }

    /**
     * The ceiling is reported in the unit it was written in. A number an
     * operator has to divide by 1024 to recognise is a number they will
     * misread while deciding whether to raise it.
     *
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function oversizedProvider(): array
    {
        return [
            'kibibytes' => ['1K', '1 KiB'],
            'mebibytes' => ['1M', '1 MiB'],
            'a number that is no whole unit' => [1500, '1500 bytes'],
            'under a kibibyte' => [64, '64 bytes'],
        ];
    }

    /**
     * The read itself is bounded, so an oversized body is detectable without
     * ever being held. Reading it all and measuring afterwards is the obvious
     * shape and is the exact failure this guards against.
     */
    public function testTheReadIsBoundedNotJustTheCheck(): void
    {
        $asked = null;
        $fetcher = new class ($asked) extends HttpFetcher {
            public function __construct(public mixed &$asked)
            {
                parent::__construct();
            }

            protected function readStream(SourceDefinition $sourceDefinition, string $url, array $options): array
            {
                $this->asked = $sourceDefinition->upstream->maxSize;

                return ["10.0.0.1\n", ['HTTP/1.1 200 OK']];
            }
        };

        $this->loader($fetcher)->load(SourceDefinition::fromArray([
            'upstream' => ['url' => 'https://example.org/list.txt', 'max_size' => '1K'],
        ]));

        $this->assertSame(1024, $asked, 'The fetcher must know the ceiling at read time, not after it');
    }

    public function testAnEntryCeilingIsEnforced(): void
    {
        $path = $this->fixture('many.txt', "10.0.0.1\n10.0.0.2\n10.0.0.3\n");

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('produced 3 entries, beyond the 2 allowed by max_entries');

        $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => $path,
            'max_entries' => 2,
        ]));
    }

    public function testAnEntryCeilingAllowsExactlyItsLimit(): void
    {
        $path = $this->fixture('exact.txt', "10.0.0.1\n10.0.0.2\n");

        $this->assertCount(2, $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => $path,
            'max_entries' => 2,
        ])));
    }

    /**
     * `max_delta` needs a previous fetch to compare against and says nothing
     * about the first load. A ceiling is an absolute statement and applies to it.
     */
    public function testTheEntryCeilingAppliesToTheFirstLoadUnlikeMaxDelta(): void
    {
        $delta = $this->fixture('delta.txt', "10.0.0.1\n10.0.0.2\n10.0.0.3\n");
        $ceiling = $this->fixture('ceiling.txt', "10.0.0.1\n10.0.0.2\n10.0.0.3\n");

        $this->assertCount(
            3,
            $this->loader()->load(SourceDefinition::fromArray(['upstream' => $delta, 'max_delta' => 0.01])),
            'max_delta has nothing to compare a first load against, and says nothing about it'
        );

        $this->expectException(SourceException::class);
        $this->loader()->load(SourceDefinition::fromArray(['upstream' => $ceiling, 'max_entries' => 2]));
    }

    /**
     * A ceiling bounds what a refresh may bring *in*. It does not retroactively
     * reject a list already cached, and deliberately so: the fallback for a
     * refused load is `last_known_good`, which is that same cached list, so
     * throwing on the cache path would log an error on every load and serve the
     * list anyway. `max_delta` has always behaved this way; this matches it.
     *
     * Consequence worth knowing, and documented: adding `max_entries` takes
     * effect on the next fetch, not the next request.
     */
    public function testACeilingDoesNotRetroactivelyRejectAnAlreadyCachedList(): void
    {
        $path = $this->fixture('cached.txt', "10.0.0.1\n10.0.0.2\n10.0.0.3\n");

        $this->assertCount(3, $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => $path,
            'name' => 'a-feed',
        ])));

        // `max_entries` is not part of the fingerprint — it changes whether a
        // load is accepted, not what a body decodes to — so this reads the
        // cache the first load warmed.
        $this->assertCount(3, $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => $path,
            'name' => 'a-feed',
            'max_entries' => 2,
        ])));
    }

    #[DataProvider('badEntryCeilingProvider')]
    public function testAnEntryCeilingThatCannotBeReadIsRefused(mixed $declared): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('"max_entries" must be a positive integer');

        SourceDefinition::fromArray(['upstream' => '/list.txt', 'max_entries' => $declared]);
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function badEntryCeilingProvider(): array
    {
        return [
            'zero' => [0],
            'negative' => [-5],
            'prose' => ['lots'],
            'a list' => [[10]],
        ];
    }

    /**
     * The case the issue names: a CDN returning an HTML error page where a text
     * file should be. It is small, decodes as `txt` without complaint, and
     * produces a few lines that are not addresses.
     */
    public function testAnErrorPageWhereAListShouldBeFailsTheSource(): void
    {
        $path = $this->fixture('oops.txt', "<html>\n<head><title>404 Not Found</title></head>\n<body>nope</body>\n</html>\n");

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('every one of its 4 entries failed `validate: cidr`');

        $this->loader()->load(SourceDefinition::fromArray([
            'upstream' => $path,
            'validate' => 'cidr',
        ]));
    }

    /**
     * And what that failure buys: the rule keeps the list that was working an
     * hour ago, rather than quietly matching nothing.
     */
    public function testAnErrorPageLeavesTheLastGoodListInPlace(): void
    {
        $path = $this->fixture('feed.txt', "203.0.113.7\n198.51.100.23\n");
        $declaration = ['upstream' => $path, 'validate' => 'cidr', 'name' => 'a-feed'];
        $sourceManager = new SourceManager($this->loader(), $this->cache());

        $this->assertCount(2, $sourceManager->load([$declaration], true));

        file_put_contents($path, "<html><body>502 Bad Gateway</body></html>\n");

        $this->assertSame(
            ['203.0.113.7', '198.51.100.23'],
            $sourceManager->load([$declaration], true),
            'An error page emptied the rule instead of being refused'
        );
    }

    /**
     * One malformed line in a 9,000-entry list must still not take the other
     * 8,999 with it. The escalation is about a source that produced nothing,
     * not about a source with problems.
     */
    public function testOneBadLineAmongGoodOnesIsStillJustDropped(): void
    {
        $path = $this->fixture('mostly-good.txt', "203.0.113.7\nnot-an-address\n198.51.100.23\n");

        $this->assertSame(
            ['203.0.113.7', '198.51.100.23'],
            $this->loader()->load(SourceDefinition::fromArray([
                'upstream' => $path,
                'validate' => 'cidr',
            ]))
        );
    }

    /**
     * Separate from `filter()`, which drops entries one at a time and is right
     * to return an empty list when every one of them is bad. Folding this into
     * it broke the tests saying so, and those tests were right.
     */
    public function testTheValidatorStillDropsRatherThanThrows(): void
    {
        $this->assertSame([], (new EntryValidator())->filter(['nope', 'also nope'], 'cidr', 'a-feed'));
    }

    /**
     * A source with no `validate` has nothing to have failed, so an empty
     * result is just an empty list — which is a legitimate thing for a feed to
     * publish on a quiet day.
     */
    public function testAnUnvalidatedSourceIsNeverEmptiedByThisCheck(): void
    {
        $entryValidator = new EntryValidator();

        $entryValidator->assertNotEmptied(['anything'], [], null, 'a-feed');
        $entryValidator->assertNotEmptied([], [], 'cidr', 'a-feed');

        $this->assertTrue(true, 'Neither shape is a source that emptied itself');
    }

    private function fixture(string $name, string $contents): string
    {
        $path = $this->workspace . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }

    private function loader(?HttpFetcher $httpFetcher = null): SourceLoader
    {
        return new SourceLoader(
            sourceCache: $this->cache(),
            fetchers: $httpFetcher instanceof HttpFetcher
                ? [new \Kanopi\Firewall\Source\Fetcher\LocalFetcher(), $httpFetcher]
                : null
        );
    }

    private function cache(): SourceCache
    {
        return new SourceCache($this->workspace . '/cache');
    }
}
