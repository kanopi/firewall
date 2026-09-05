<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests the store that holds post-pipeline entries rather than raw bodies.
 */
class SourceCacheTest extends AbstractTestCase
{
    /**
     * Scratch cache directory.
     */
    private string $directory;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->directory = sys_get_temp_dir() . '/firewall-cache-' . bin2hex(random_bytes(6));
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->directory);
        parent::tearDown();
    }

    /**
     * A definition to cache against.
     */
    private function definition(array $overrides = []): SourceDefinition
    {
        return SourceDefinition::fromArray(['upstream' => '/lists/a.txt'] + $overrides);
    }

    /**
     * Nothing cached reads as nothing, not as an error.
     */
    public function testEmptyCache(): void
    {
        $cache = new SourceCache($this->directory);

        $this->assertSame([], $cache->meta($this->definition()));
        $this->assertNull($cache->entries($this->definition()));
    }

    /**
     * Entries round-trip through the store.
     */
    public function testEntriesRoundTrip(): void
    {
        $cache = new SourceCache($this->directory);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1', '2.2.2.2'], ['etag' => 'W/"v1"']);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $cache->entries($definition));
    }

    /**
     * Structured entries survive the round trip too.
     */
    public function testStructuredEntriesRoundTrip(): void
    {
        $cache = new SourceCache($this->directory);
        $definition = $this->definition();
        $entries = [['type' => 'AND', 'rules' => ['a:b', 'c:d']]];

        $cache->store($definition, $entries, []);

        $this->assertSame($entries, $cache->entries($definition));
    }

    /**
     * Metadata carries the validators and counters forward.
     */
    public function testMetadataIsStored(): void
    {
        $cache = new SourceCache($this->directory);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], ['etag' => 'W/"v1"', 'body_hash' => 'abc']);
        $meta = $cache->meta($definition);

        $this->assertSame('W/"v1"', $meta['etag']);
        $this->assertSame('abc', $meta['body_hash']);
        $this->assertSame(1, $meta['entry_count']);
        $this->assertIsInt($meta['fetched_at']);
    }

    /**
     * Freshness is judged against the source's own TTL.
     */
    public function testFreshness(): void
    {
        $cache = new SourceCache($this->directory);

        $this->assertTrue($cache->isFresh($this->definition(['ttl' => 60]), ['fetched_at' => time()]));
        $this->assertFalse($cache->isFresh($this->definition(['ttl' => 60]), ['fetched_at' => time() - 120]));
        $this->assertFalse($cache->isFresh($this->definition(['ttl' => 0]), ['fetched_at' => time()]));
        $this->assertFalse($cache->isFresh($this->definition(), []));
    }

    /**
     * A declared TTL beats the global default.
     */
    public function testDeclaredTtlWins(): void
    {
        $cache = new SourceCache($this->directory);

        $this->assertSame(21600, $cache->ttl($this->definition(['ttl' => 21600])));
        $this->assertSame(3600, $cache->ttl($this->definition()));
    }

    /**
     * Two sources with different pipelines do not share a cache entry.
     */
    public function testDistinctPipelinesDoNotCollide(): void
    {
        $cache = new SourceCache($this->directory);
        $first = $this->definition(['template' => '{value[a]}']);
        $second = $this->definition(['template' => '{value[b]}']);

        $cache->store($first, ['one'], []);
        $cache->store($second, ['two'], []);

        $this->assertSame(['one'], $cache->entries($first));
        $this->assertSame(['two'], $cache->entries($second));
    }

    /**
     * A cached source can be discarded.
     */
    public function testForget(): void
    {
        $cache = new SourceCache($this->directory);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], []);
        $cache->forget($definition);

        $this->assertNull($cache->entries($definition));
        $this->assertSame([], $cache->meta($definition));
    }

    /**
     * Entries are written as a plain PHP array so opcache can hold them,
     * which is what makes a warm request an include rather than a parse.
     */
    public function testEntriesAreStoredAsPhp(): void
    {
        $cache = new SourceCache($this->directory);
        $cache->store($this->definition(), ['1.1.1.1'], []);

        $files = glob($this->directory . '/*.php') ?: [];

        $this->assertCount(1, $files);
        $this->assertStringStartsWith('<?php', (string) file_get_contents($files[0]));
    }

    /**
     * An explicit directory beats the derived default.
     */
    public function testExplicitDirectory(): void
    {
        $this->assertSame($this->directory, (new SourceCache($this->directory))->directory());
        $this->assertStringContainsString('kanopi-firewall-sources', (new SourceCache())->directory());
    }
}
