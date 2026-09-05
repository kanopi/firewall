<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\FetchResult;
use Kanopi\Firewall\Source\Fetcher\FetcherInterface;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Tests the end-to-end source pipeline across every supported format.
 */
class SourceLoaderTest extends AbstractTestCase
{
    /**
     * Scratch directory for fixtures and cache files.
     */
    private string $workspace;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-sources-' . bin2hex(random_bytes(6));
        mkdir($this->workspace . '/cache', 0775, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        $this->removeDirectory($this->workspace);
        parent::tearDown();
    }

    /**
     * Remove a directory tree.
     */
    private function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $directory . '/' . $entry;
            is_dir($path) ? $this->removeDirectory($path) : @unlink($path);
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
     * A loader writing into the scratch cache.
     */
    private function loader(?FetcherInterface $fetcher = null, ?bool $offline = null): SourceLoader
    {
        return new SourceLoader(
            sourceCache: new SourceCache($this->workspace . '/cache'),
            fetchers: $fetcher === null ? null : [$fetcher],
            offline: $offline
        );
    }

    /**
     * Each format decodes, selects, filters, and renders to the same entries.
     */
    #[DataProvider('formatPipelineProvider')]
    public function testPipelineAcrossFormats(string $file, string $contents, array $options, array $expected): void
    {
        $definition = SourceDefinition::fromArray(
            ['upstream' => $this->fixture($file, $contents)] + $options
        );

        $this->assertSame($expected, $this->loader()->load($definition));
    }

    /**
     * The same EC2 selection expressed in every supported format.
     */
    public static function formatPipelineProvider(): array
    {
        return [
            'txt passes lines through' => [
                'ips.txt',
                "# banner\n3.5.140.0/22\n18.34.32.0/20 # ec2\n",
                [],
                ['3.5.140.0/22', '18.34.32.0/20'],
            ],
            'txt filtered by value' => [
                'ips2.txt',
                "10.0.0.1\n192.168.0.1\n10.0.0.2",
                ['where' => ['value@starts_with:10.']],
                ['10.0.0.1', '10.0.0.2'],
            ],
            'json select where template' => [
                'ranges.json',
                '{"prefixes":[' .
                '{"ip_prefix":"3.5.140.0/22","service":"S3"},' .
                '{"ip_prefix":"18.34.32.0/20","service":"EC2"}]}',
                [
                    'select' => 'prefixes.*',
                    'where' => ['service:EC2'],
                    'template' => '{value[ip_prefix]}',
                ],
                ['18.34.32.0/20'],
            ],
            'json alternation across collections' => [
                'ranges6.json',
                '{"prefixes":[{"ip_prefix":"18.34.32.0/20","service":"EC2"}],' .
                '"ipv6_prefixes":[{"ipv6_prefix":"2600:1f01::/40","service":"EC2"}]}',
                [
                    'select' => '{prefixes,ipv6_prefixes}.*',
                    'where' => ['service:EC2'],
                    'template' => '{value[ip_prefix|ipv6_prefix]}',
                ],
                ['18.34.32.0/20', '2600:1f01::/40'],
            ],
            'ndjson' => [
                'feed.ndjson',
                "{\"ip\":\"1.1.1.1\",\"score\":90}\n{\"ip\":\"2.2.2.2\",\"score\":10}",
                [
                    'where' => ['score@greater_than:50'],
                    'template' => '{value[ip]}',
                ],
                ['1.1.1.1'],
            ],
            'yaml list' => [
                'list.yml',
                "- 1.2.3.4\n- 5.6.7.8",
                [],
                ['1.2.3.4', '5.6.7.8'],
            ],
            'yaml nested with select' => [
                'nested.yml',
                "paths:\n  - path: /admin\n    confidence: 90\n  - path: /robots.txt\n    confidence: 10",
                [
                    'select' => 'paths.*',
                    'where' => ['confidence@greater_than:50'],
                    'template' => 'path@starts_with:{value[path]}',
                ],
                ['path@starts_with:/admin'],
            ],
            'csv with headers' => [
                'asns.csv',
                "asn,org\n13335,CLOUDFLARENET\n16509,AMAZON-02",
                ['template' => 'asn:{value[asn]}'],
                ['asn:13335', 'asn:16509'],
            ],
            'csv without a header row' => [
                'asns2.csv',
                "13335,CLOUDFLARENET",
                ['header_row' => false, 'template' => 'asn:{value[0]}'],
                ['asn:13335'],
            ],
            'tsv' => [
                'asns.tsv',
                "asn\torg\n13335\tCLOUDFLARENET",
                ['template' => 'asn:{value[asn]}'],
                ['asn:13335'],
            ],
        ];
    }

    /**
     * A map template builds the grouped rules Url and UserAgent accept.
     */
    public function testMapTemplateProducesGroupedRules(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => $this->fixture('sigs.json', '[{"name":"sqlmap","is_bot":true}]'),
            'template' => [
                'type' => 'AND',
                'rules' => ['client.name@contains:{value[name]}', 'bot:{value[is_bot]}'],
            ],
        ]);

        $this->assertSame([
            ['type' => 'AND', 'rules' => ['client.name@contains:sqlmap', 'bot:true']],
        ], $this->loader()->load($definition));
    }

    /**
     * A gzipped body is decompressed before decoding.
     */
    public function testGzipCompression(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => $this->fixture('ips.txt.gz', (string) gzencode("1.2.3.4\n5.6.7.8")),
        ]);

        $this->assertSame('gzip', $definition->compression);
        $this->assertSame(['1.2.3.4', '5.6.7.8'], $this->loader()->load($definition));
    }

    /**
     * A body that is not valid gzip is an error rather than garbage entries.
     */
    public function testInvalidGzipIsRejected(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => $this->fixture('bad.txt.gz', 'not actually gzipped'),
        ]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('not valid gzip');

        $this->loader()->load($definition);
    }

    /**
     * Entries failing validation are dropped, keeping the rest.
     */
    public function testValidationDropsBadEntries(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => $this->fixture('mixed.txt', "1.2.3.4\nnonsense\n10.0.0.0/8"),
            'validate' => 'cidr',
        ]);

        $this->assertSame(['1.2.3.4', '10.0.0.0/8'], $this->loader()->load($definition));
    }

    /**
     * A missing local file is an error the caller can act on.
     */
    public function testMissingLocalFile(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => $this->workspace . '/absent.txt']);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('cannot read');

        $this->loader()->load($definition);
    }

    /**
     * A second load inside the TTL is served from cache without re-reading.
     */
    public function testFreshCacheIsReusedWithoutRefetching(): void
    {
        $path = $this->fixture('cached.txt', "1.1.1.1");
        $definition = SourceDefinition::fromArray(['upstream' => $path, 'ttl' => 3600]);
        $loader = $this->loader();

        $this->assertSame(['1.1.1.1'], $loader->load($definition));

        // Change the file behind the loader's back. A fresh cache means the
        // new contents are not picked up until the TTL lapses.
        file_put_contents($path, "9.9.9.9");

        $this->assertSame(['1.1.1.1'], $loader->load($definition));
    }

    /**
     * Forcing a load revalidates regardless of freshness.
     */
    public function testForceBypassesFreshness(): void
    {
        $path = $this->fixture('forced.txt', "1.1.1.1");
        $definition = SourceDefinition::fromArray(['upstream' => $path, 'ttl' => 3600]);
        $loader = $this->loader();

        $loader->load($definition);
        file_put_contents($path, "9.9.9.9");

        $this->assertSame(['9.9.9.9'], $loader->load($definition, true));
    }

    /**
     * An upstream reporting no change reuses cached entries rather than
     * re-running the pipeline.
     */
    public function testNotModifiedReusesCachedEntries(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt', 'ttl' => 0]);

        $fetcher = new class implements FetcherInterface {
            public int $calls = 0;

            public function supports(SourceDefinition $definition): bool
            {
                return true;
            }

            public function fetch(SourceDefinition $definition, array $validators = []): FetchResult
            {
                $this->calls++;

                if ($this->calls === 1) {
                    return new FetchResult("1.1.1.1\n2.2.2.2", false, 'W/"v1"');
                }

                return FetchResult::unchanged($validators['etag'] ?? null);
            }
        };

        $loader = $this->loader($fetcher);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));
        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));
        $this->assertSame(2, $fetcher->calls);
    }

    /**
     * The stored validators are sent back on the next fetch, which is what
     * lets an upstream answer 304 instead of resending the body.
     */
    public function testValidatorsArePresentedOnRefetch(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt', 'ttl' => 0]);

        $fetcher = new class implements FetcherInterface {
            /** @var array<int, array<string, mixed>> */
            public array $seen = [];

            public function supports(SourceDefinition $definition): bool
            {
                return true;
            }

            public function fetch(SourceDefinition $definition, array $validators = []): FetchResult
            {
                $this->seen[] = $validators;

                return new FetchResult('1.1.1.1', false, 'W/"v1"', 'Wed, 03 Sep 2026 18:02:00 GMT');
            }
        };

        $loader = $this->loader($fetcher);
        $loader->load($definition);
        $loader->load($definition);

        $this->assertNull($fetcher->seen[0]['etag']);
        $this->assertSame('W/"v1"', $fetcher->seen[1]['etag']);
        $this->assertSame('Wed, 03 Sep 2026 18:02:00 GMT', $fetcher->seen[1]['last_modified']);
    }

    /**
     * An upstream with no conditional-request support still avoids the decode
     * when the body hashes to what produced the cached entries.
     */
    public function testIdenticalBodySkipsThePipeline(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => 'https://example.org/list.txt',
            'ttl' => 0,
            'max_delta' => 0.0,
        ]);

        $fetcher = new class implements FetcherInterface {
            public function supports(SourceDefinition $definition): bool
            {
                return true;
            }

            public function fetch(SourceDefinition $definition, array $validators = []): FetchResult
            {
                return new FetchResult("1.1.1.1\n2.2.2.2");
            }
        };

        $loader = $this->loader($fetcher);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));

        // A zero max_delta would reject any recount, so reaching the same
        // answer twice proves the pipeline was skipped rather than rerun.
        $this->assertSame(['1.1.1.1', '2.2.2.2'], $loader->load($definition));
    }

    /**
     * A refresh that collapses the list is rejected before it reaches a plugin.
     */
    public function testMaxDeltaRejectsCollapse(): void
    {
        $path = $this->fixture('delta.txt', implode("\n", array_map(
            static fn (int $i): string => sprintf('10.0.%d.1', $i),
            range(1, 20)
        )));

        $definition = SourceDefinition::fromArray([
            'upstream' => $path,
            'ttl' => 0,
            'max_delta' => 0.25,
        ]);

        $loader = $this->loader();
        $this->assertCount(20, $loader->load($definition));

        file_put_contents($path, "10.0.1.1");

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('beyond the 25.0% allowed');

        $loader->load($definition);
    }

    /**
     * Offline mode serves a remote source from cache without any fetch.
     */
    public function testOfflineServesFromCache(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt', 'ttl' => 0]);

        $fetcher = new class implements FetcherInterface {
            public int $calls = 0;

            public function supports(SourceDefinition $definition): bool
            {
                return true;
            }

            public function fetch(SourceDefinition $definition, array $validators = []): FetchResult
            {
                $this->calls++;

                return new FetchResult('1.1.1.1');
            }
        };

        $this->loader($fetcher)->load($definition);
        $this->assertSame(1, $fetcher->calls);

        $offline = $this->loader($fetcher, true);

        $this->assertSame(['1.1.1.1'], $offline->load($definition));
        $this->assertSame(1, $fetcher->calls, 'Offline mode must not reach the network.');
    }

    /**
     * Offline mode with nothing cached is an error rather than a silent empty
     * rule list — the failure a deployment needs to hear about.
     */
    public function testOfflineWithoutCacheFails(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => 'https://example.org/missing.txt']);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('running offline with nothing cached');

        $this->loader(null, true)->load($definition);
    }

    /**
     * Offline mode still reads local files, which is the intended arrangement:
     * sync to disk out of band, serve from disk.
     */
    public function testOfflineStillReadsLocalFiles(): void
    {
        $definition = SourceDefinition::fromArray([
            'upstream' => $this->fixture('local.txt', '1.2.3.4'),
        ]);

        $this->assertSame(['1.2.3.4'], $this->loader(null, true)->load($definition));
    }

    /**
     * Editing the pipeline invalidates the cache even though the file did not
     * change, because the fingerprint covers select and template.
     */
    public function testChangingThePipelineInvalidatesTheCache(): void
    {
        $path = $this->fixture('shape.json', '[{"a":"one","b":"two"}]');
        $loader = $this->loader();

        $first = SourceDefinition::fromArray([
            'upstream' => $path,
            'template' => '{value[a]}',
            'ttl' => 3600,
        ]);
        $second = SourceDefinition::fromArray([
            'upstream' => $path,
            'template' => '{value[b]}',
            'ttl' => 3600,
        ]);

        $this->assertSame(['one'], $loader->load($first));
        $this->assertSame(['two'], $loader->load($second));
    }

    /**
     * A source with no fetcher that handles it reports so plainly.
     */
    public function testNoFetcherForUpstream(): void
    {
        $definition = SourceDefinition::fromArray(['upstream' => 'https://example.org/list.txt']);

        $fetcher = new class implements FetcherInterface {
            public function supports(SourceDefinition $definition): bool
            {
                return false;
            }

            public function fetch(SourceDefinition $definition, array $validators = []): FetchResult
            {
                return new FetchResult('');
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('no fetcher handles');

        $this->loader($fetcher)->load($definition);
    }
}
