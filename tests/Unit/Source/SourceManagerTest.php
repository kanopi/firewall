<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Tests merging several sources and the failure policy governing each.
 */
class SourceManagerTest extends AbstractTestCase
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
        $this->workspace = sys_get_temp_dir() . '/firewall-manager-' . bin2hex(random_bytes(6));
        mkdir($this->workspace . '/cache', 0775, true);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        foreach (glob($this->workspace . '/{,cache/}*', GLOB_BRACE) ?: [] as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->workspace . '/cache');
        @rmdir($this->workspace);
        parent::tearDown();
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
     * A manager writing into the scratch cache.
     */
    private function manager(): SourceManager
    {
        $cache = new SourceCache($this->workspace . '/cache');

        return new SourceManager(new SourceLoader($cache), $cache);
    }

    /**
     * Sources contribute in declaration order, concatenated.
     */
    public function testSourcesMergeInDeclarationOrder(): void
    {
        $entries = $this->manager()->load([
            ['name' => 'circleci', 'upstream' => $this->fixture('a.txt', "3.228.39.90/32\n18.213.67.41/32")],
            ['name' => 'uptimerobot', 'upstream' => $this->fixture('b.txt', "216.144.250.150/32")],
        ]);

        $this->assertSame([
            '3.228.39.90/32',
            '18.213.67.41/32',
            '216.144.250.150/32',
        ], $entries);
    }

    /**
     * A bare string is shorthand for `{upstream: ...}`, decoded by extension.
     */
    public function testStringShorthand(): void
    {
        $entries = $this->manager()->load([$this->fixture('short.txt', '1.2.3.4')]);

        $this->assertSame(['1.2.3.4'], $entries);
    }

    /**
     * Every entry can be attributed back to the source that produced it.
     */
    public function testProvenanceTracksEachEntry(): void
    {
        $manager = $this->manager();
        $manager->load([
            ['name' => 'circleci', 'upstream' => $this->fixture('c.txt', "1.1.1.1\n2.2.2.2")],
            ['name' => 'tor', 'upstream' => $this->fixture('d.txt', '3.3.3.3')],
        ]);

        $this->assertSame([
            0 => 'circleci',
            1 => 'circleci',
            2 => 'tor',
        ], $manager->provenance());
    }

    /**
     * A failing source is skipped and the others still load — right for a
     * block list, where losing coverage beats losing the site.
     */
    public function testFailingSourceDoesNotDiscardTheOthers(): void
    {
        $manager = $this->manager();

        $entries = $manager->load([
            ['name' => 'good', 'upstream' => $this->fixture('good.txt', '1.1.1.1')],
            ['name' => 'missing', 'upstream' => $this->workspace . '/absent.txt', 'on_error' => 'fail_open'],
        ]);

        $this->assertSame(['1.1.1.1'], $entries);
        $this->assertCount(1, $manager->errors());
        $this->assertSame('missing', $manager->errors()[0]['source']);
    }

    /**
     * `required: true` aborts instead of degrading — what an allow list wants,
     * since silently dropping it narrows what is permitted.
     */
    public function testRequiredSourceAborts(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('cannot read');

        $this->manager()->load([
            ['name' => 'ci-ranges', 'upstream' => $this->workspace . '/absent.txt', 'required' => true],
        ]);
    }

    /**
     * `on_error: abort` aborts without needing `required`.
     */
    public function testAbortPolicyAborts(): void
    {
        $this->expectException(SourceException::class);

        $this->manager()->load([
            ['upstream' => $this->workspace . '/absent.txt', 'on_error' => 'abort'],
        ]);
    }

    /**
     * The default policy falls back to the last good copy, so a source that
     * breaks after a successful load keeps working.
     */
    public function testLastKnownGoodFallback(): void
    {
        $path = $this->fixture('flaky.txt', "1.1.1.1\n2.2.2.2");
        $declaration = ['name' => 'flaky', 'upstream' => $path, 'ttl' => 0];

        $manager = $this->manager();
        $this->assertSame(['1.1.1.1', '2.2.2.2'], $manager->load([$declaration]));

        unlink($path);

        $this->assertSame(['1.1.1.1', '2.2.2.2'], $manager->load([$declaration]));
        $this->assertCount(1, $manager->errors());
    }

    /**
     * With no cached copy to fall back to, the source contributes nothing and
     * says so rather than pretending to have loaded.
     */
    public function testLastKnownGoodWithoutCacheContributesNothing(): void
    {
        $manager = $this->manager();

        $this->assertSame([], $manager->load([
            ['name' => 'never-loaded', 'upstream' => $this->workspace . '/absent.txt'],
        ]));

        $this->assertCount(1, $manager->errors());
    }

    /**
     * `fail_open` skips the cache entirely and contributes nothing.
     */
    public function testFailOpenIgnoresTheCache(): void
    {
        $path = $this->fixture('open.txt', '1.1.1.1');
        $declaration = ['name' => 'open', 'upstream' => $path, 'ttl' => 0, 'on_error' => 'fail_open'];

        $manager = $this->manager();
        $manager->load([$declaration]);

        unlink($path);

        $this->assertSame([], $manager->load([$declaration]));
    }

    /**
     * A malformed declaration always throws: there is no degraded behaviour
     * for a source nobody can interpret.
     */
    public function testMalformedDeclarationThrows(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('must be a map or a string');

        $this->manager()->load([42]);
    }

    /**
     * An invalid option throws at declaration time, before any fetching.
     */
    public function testInvalidOptionThrowsBeforeFetching(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('must be one of');

        $this->manager()->load([['upstream' => '/x.txt', 'format' => 'toml']]);
    }

    /**
     * Loading twice resets the recorded errors and provenance.
     */
    public function testStateResetsBetweenLoads(): void
    {
        $manager = $this->manager();

        $manager->load([['name' => 'missing', 'upstream' => $this->workspace . '/absent.txt']]);
        $this->assertCount(1, $manager->errors());

        $manager->load([['name' => 'good', 'upstream' => $this->fixture('reset.txt', '1.1.1.1')]]);

        $this->assertSame([], $manager->errors());
        $this->assertSame([0 => 'good'], $manager->provenance());
    }

    /**
     * No declarations is not an error.
     */
    public function testNoDeclarations(): void
    {
        $this->assertSame([], $this->manager()->load([]));
    }
}
