<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * Covers the cache's failure paths and its constant-driven configuration.
 *
 * A cache that cannot write must degrade rather than throw — a source whose
 * result cannot be stored should still be usable this request, and the next
 * request can try again. These tests pin that.
 */
class SourceCacheEdgeTest extends AbstractTestCase
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
        $this->workspace = sys_get_temp_dir() . '/firewall-cache-edge-' . bin2hex(random_bytes(6));
        mkdir($this->workspace, 0775, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        @chmod($this->workspace, 0775);

        foreach (glob($this->workspace . '/*') ?: [] as $path) {
            @chmod($path, 0775);

            if (is_dir($path)) {
                foreach (glob($path . '/*') ?: [] as $inner) {
                    @unlink($inner);
                }

                @rmdir($path);
                continue;
            }

            @unlink($path);
        }

        @rmdir($this->workspace);
        parent::tearDown();
    }

    /**
     * A definition to cache against.
     */
    private function definition(): SourceDefinition
    {
        return SourceDefinition::fromArray(['upstream' => '/lists/a.txt']);
    }

    /**
     * Unreadable metadata reads as none rather than throwing.
     */
    public function testUnreadableMetadataReadsAsEmpty(): void
    {
        $cache = new SourceCache($this->workspace);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], ['etag' => 'v1']);

        // Corrupt the metadata the way a truncated write would.
        foreach (glob($this->workspace . '/*.json') ?: [] as $file) {
            file_put_contents($file, 'not json at all');
        }

        $this->assertSame([], $cache->meta($definition));
    }

    /**
     * Entries that are not a PHP array read as nothing.
     */
    public function testCorruptEntriesFileReadsAsNothing(): void
    {
        $cache = new SourceCache($this->workspace);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], []);

        foreach (glob($this->workspace . '/*.php') ?: [] as $file) {
            file_put_contents($file, '<?php return "not an array";');
        }

        $this->assertNull($cache->entries($definition));
    }

    /**
     * A cache directory that cannot be created degrades instead of throwing.
     *
     * The source still produced its entries; only the caching of them failed,
     * and that should cost performance rather than the ruleset.
     */
    public function testUncreatableDirectoryDegradesQuietly(): void
    {
        $readOnly = $this->workspace . '/locked';
        mkdir($readOnly, 0555, true);

        $cache = new SourceCache($readOnly . '/cannot-create');
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], []);

        $this->assertNull($cache->entries($definition), 'Nothing was stored, and nothing blew up.');
    }

    /**
     * A write into a directory that exists but is not writable degrades too.
     */
    public function testUnwritableDirectoryDegradesQuietly(): void
    {
        $directory = $this->workspace . '/readonly';
        mkdir($directory, 0755, true);
        chmod($directory, 0555);

        $cache = new SourceCache($directory);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], []);

        $this->assertNull($cache->entries($definition));
    }

    /**
     * Publishing over something that cannot be replaced degrades too.
     *
     * The staged temporary file is renamed into place; when the destination is
     * a directory the rename cannot succeed.
     */
    public function testUnpublishableTargetDegradesQuietly(): void
    {
        $cache = new SourceCache($this->workspace);
        $definition = $this->definition();

        // Occupy the entries path with a directory so the rename fails.
        $entriesPath = $this->workspace . '/' . substr($definition->fingerprint(), 0, 32) . '.php';
        mkdir($entriesPath, 0755, true);

        $cache->store($definition, ['1.1.1.1'], []);

        $this->assertNull($cache->entries($definition));
    }

    /**
     * Forgetting a source that was never stored is not an error.
     */
    public function testForgettingAnUncachedSourceIsSafe(): void
    {
        $this->expectNotToPerformAssertions();

        (new SourceCache($this->workspace))->forget($this->definition());
    }

    /**
     * The global TTL constant is the fallback when a source declares none.
     */
    #[RunInSeparateProcess]
    public function testGlobalTtlConstantIsUsed(): void
    {
        define('KANOPI_FIREWALL_CACHE_TTL', 4242);

        $this->assertSame(4242, (new SourceCache($this->workspace))->ttl($this->definition()));
    }

    /**
     * A source's own TTL still wins over the constant.
     */
    #[RunInSeparateProcess]
    public function testDeclaredTtlBeatsTheConstant(): void
    {
        define('KANOPI_FIREWALL_CACHE_TTL', 4242);

        $definition = SourceDefinition::fromArray(['upstream' => '/a.txt', 'ttl' => 60]);

        $this->assertSame(60, (new SourceCache($this->workspace))->ttl($definition));
    }

    /**
     * The global cache directory constant places sources under it.
     */
    #[RunInSeparateProcess]
    public function testGlobalCacheDirectoryConstantIsUsed(): void
    {
        define('KANOPI_FIREWALL_CACHE_DIR', '/var/cache/firewall/');

        $this->assertSame('/var/cache/firewall/sources', (new SourceCache())->directory());
    }

    /**
     * Metadata that exists but cannot be read reads as none.
     */
    public function testUnreadableMetadataFileReadsAsEmpty(): void
    {
        $cache = new SourceCache($this->workspace);
        $definition = $this->definition();

        $cache->store($definition, ['1.1.1.1'], ['etag' => 'v1']);

        $metaFiles = glob($this->workspace . '/*.json') ?: [];
        $this->assertNotSame([], $metaFiles);

        if (!chmod($metaFiles[0], 0000) || is_readable($metaFiles[0])) {
            // Running as a user who can read anything — root in a container,
            // typically. The branch is unreachable there.
            $this->markTestSkipped('Cannot make a file unreadable as this user.');
        }

        $this->assertSame([], $cache->meta($definition));
    }
}
