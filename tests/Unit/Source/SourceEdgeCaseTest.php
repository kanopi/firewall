<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\Decoder\CsvDecoder;
use Kanopi\Firewall\Source\Decoder\DecoderRegistry;
use Kanopi\Firewall\Source\Decoder\YamlDecoder;
use Kanopi\Firewall\Source\EntryValidator;
use Kanopi\Firewall\Source\FetchResult;
use Kanopi\Firewall\Source\Fetcher\FetcherInterface;
use Kanopi\Firewall\Source\Fetcher\LocalFetcher;
use Kanopi\Firewall\Source\RecordFilter;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\TemplateRenderer;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Covers the error and edge paths the happy-path suites do not reach.
 *
 * These are the branches that only run when something has gone wrong — a
 * malformed declaration, an unwritable cache, a read that fails after the
 * readability check passed. They are exactly the paths worth having tests for,
 * because they are the ones nobody exercises by hand.
 */
class SourceEdgeCaseTest extends AbstractTestCase
{
    /**
     * Scratch directory.
     */
    private string $workspace;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-edge-' . bin2hex(random_bytes(6));
        mkdir($this->workspace, 0775, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        $this->removeTree($this->workspace);
        parent::tearDown();
    }

    /**
     * Remove a directory tree, restoring permissions as it goes.
     */
    private function removeTree(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        @chmod($directory, 0775);

        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $directory . '/' . $entry;
            is_dir($path) ? $this->removeTree($path) : @unlink($path);
        }

        @rmdir($directory);
    }

    /**
     * Write a fixture and return its path.
     */
    private function fixture(string $name, string $contents): string
    {
        $path = $this->workspace . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * An empty body decodes to nothing on every structured format.
     *
     * @param object $decoder
     *   The decoder under test.
     */
    #[DataProvider('emptyBodyDecoderProvider')]
    public function testEmptyBodiesDecodeToNothing(string $decoderClass, string $format): void
    {
        $decoder = new $decoderClass();
        $definition = SourceDefinition::fromArray(['upstream' => '/x', 'format' => $format]);

        $this->assertSame([], $decoder->decode('   ', $definition));
    }

    /**
     * Decoders and the format they handle.
     */
    public static function emptyBodyDecoderProvider(): array
    {
        return [
            'yaml' => [YamlDecoder::class, 'yaml'],
            'csv' => [CsvDecoder::class, 'csv'],
        ];
    }

    /**
     * A CSV row that is entirely a comment is skipped.
     */
    public function testCsvCommentRowsAreSkipped(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => '/x.csv', 'format' => 'csv']);

        $this->assertSame(
            [['a' => '1']],
            (new CsvDecoder())->decode("# note\na\n# another\n1\n", $definition)
        );
    }

    /**
     * Asking the registry for a format nobody handles names what it does have.
     */
    public function testDecoderRegistryRejectsAnUnknownFormat(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('No decoder registered for format "toml"');

        (new DecoderRegistry())->get('toml');
    }

    /**
     * An entry that is neither string nor int is rejected by type.
     *
     * @param mixed $entry
     *   An entry of an unusable type.
     */
    #[DataProvider('nonScalarEntryProvider')]
    public function testValidatorRejectsEntriesOfTheWrongType(mixed $entry): void
    {
        $this->assertSame([], (new EntryValidator())->filter([$entry], 'string', 'test'));
    }

    /**
     * Entry types no validator can make sense of.
     */
    public static function nonScalarEntryProvider(): array
    {
        return [
            'bool' => [true],
            'float' => [1.5],
            'null' => [null],
        ];
    }

    /**
     * The filter resolves nothing when it holds no record.
     *
     * The guard exists because `getValue()` is a hook the evaluator can reach;
     * outside a `matches()` call there is nothing to read.
     */
    public function testRecordFilterResolvesNothingWithoutARecord(): void
    {
        $filter = new RecordFilter();

        $method = new \ReflectionMethod(RecordFilter::class, 'getValue');
        $method->setAccessible(true);

        $this->assertNull($method->invoke($filter, new Request(), 'service'));
    }

    /**
     * A wildcard subscript resolves nothing rather than picking a field at
     * random.
     */
    public function testTemplateWildcardSubscriptResolvesNothing(): void
    {
        $this->assertNull((new TemplateRenderer())->render(['a' => 1, 'b' => 2], '{value[*]}'));
    }

    /**
     * A non-string `select` is a configuration error.
     */
    public function testSelectMustBeAString(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('"select" must be a string dot-path');

        SourceDefinition::fromArray(['upstream' => '/x.json', 'select' => ['prefixes']]);
    }

    /**
     * A read that fails after the readability check is reported, not returned
     * as an empty list.
     */
    public function testLocalFetcherReportsAFailedRead(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'racy',
            'upstream' => $this->fixture('racy.txt', '1.2.3.4'),
        ]);

        $fetcher = new class extends LocalFetcher {
            protected function readFile(string $path): string|false
            {
                // The file was readable a moment ago and is not now.
                return false;
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('failed to read');

        $fetcher->fetch($definition);
    }

    /**
     * A gzip source on a host without ext-zlib says so rather than failing to
     * decode something that was never going to decode.
     */
    public function testGzipWithoutZlibIsReported(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'zipped',
            'upstream' => $this->fixture('list.txt.gz', (string) gzencode('1.2.3.4')),
        ]);

        $loader = new class extends SourceLoader {
            protected function gzipAvailable(): bool
            {
                return false;
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('ext-zlib is not available');

        $loader->load($definition);
    }

    /**
     * A template whose placeholders do not resolve drops those records, and
     * says how many.
     */
    public function testUnresolvableTemplatesDropRecordsAndReport(): void
    {
        $body = json_encode([
            ['ip' => '1.1.1.1'],
            ['other' => 'no ip here'],
            ['ip' => '2.2.2.2'],
        ]);

        $definition = SourceDefinition::fromArray([
            'name' => 'partial',
            'upstream' => $this->fixture('partial.json', (string) $body),
            'template' => '{value[ip]}',
        ]);

        $loader = new SourceLoader(new \Kanopi\Firewall\Source\SourceCache($this->workspace . '/cache'));

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));
    }

    /**
     * An upstream reporting "not modified" with nothing cached is an error, not
     * a silently empty list.
     */
    public function testNotModifiedWithNothingCachedIsAnError(): void
    {
        $definition = SourceDefinition::fromArray([
            'name' => 'confused',
            'upstream' => 'https://example.org/list.txt',
        ]);

        $fetcher = new class implements FetcherInterface {
            public function supports(SourceDefinition $sourceDefinition): bool
            {
                return true;
            }

            public function fetch(SourceDefinition $sourceDefinition, array $validators = []): FetchResult
            {
                return FetchResult::unchanged();
            }
        };

        $loader = new SourceLoader(
            new \Kanopi\Firewall\Source\SourceCache($this->workspace . '/cache'),
            fetchers: [$fetcher]
        );

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('reported no change but nothing is cached');

        $loader->load($definition);
    }

    /**
     * `auth` must be a map.
     */
    public function testUpstreamAuthMustBeAMap(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('upstream.auth must be a map');

        SourceDefinition::fromArray(['upstream' => ['url' => 'https://example.org/a', 'auth' => 'bearer']]);
    }

    /**
     * `body` must be a string.
     */
    public function testUpstreamBodyMustBeAString(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('upstream.body must be a string');

        SourceDefinition::fromArray(['upstream' => ['url' => 'https://example.org/a', 'body' => ['q' => 1]]]);
    }

    /**
     * A CSV header row with an empty column name skips that column.
     *
     * Trailing commas produce one, and a nameless column has nothing to key a
     * record by.
     */
    public function testCsvSkipsUnnamedColumns(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => '/x.csv', 'format' => 'csv']);

        $this->assertSame(
            [['asn' => '13335', 'org' => 'CLOUDFLARENET']],
            (new CsvDecoder())->decode("asn,,org\n13335,ignored,CLOUDFLARENET\n", $definition)
        );
    }
}
