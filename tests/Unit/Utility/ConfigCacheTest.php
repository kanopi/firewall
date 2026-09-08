<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;

/**
 * The compiled-configuration cache, and everything that must invalidate it (#227).
 *
 * Parsing the shipped presets costs 5.9 ms per request against a 3.07 ms page, so the
 * cache is worth having -- but a firewall serving a stale configuration is worse than a
 * slow one. These tests exist for the invalidation, not the speed.
 */
class ConfigCacheTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-config-cache-test-' . uniqid();
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
     * Write a file with a distinct mtime, so a same-second rewrite is not the thing
     * under test here.
     */
    private function write(string $name, string $contents, int $ageSeconds = 0): string
    {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, $contents);

        if ($ageSeconds > 0) {
            touch($path, time() - $ageSeconds);
        }

        return $path;
    }

    /**
     * The same request twice gives the same answer.
     */
    public function testASecondLoadReturnsTheSameConfiguration(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        $first = Config::load([$file]);
        $second = Config::load([$file]);

        $this->assertSame($first, $second);
        $this->assertSame('block', $second['global']['mode'] ?? null);
    }

    /**
     * Editing the file invalidates.
     */
    public function testEditingTheFileInvalidates(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);
        Config::load([$file]);

        $this->write('main.yml', "global:\n  mode: log\n");

        $this->assertSame('log', Config::load([$file])['global']['mode'] ?? null);
    }

    /**
     * Editing an *included* file invalidates.
     *
     * The entry point is unchanged here, so nothing about it says the result is
     * stale. Which files a configuration depends on is only discoverable by
     * having loaded it once -- `configs:` recurses and globs -- which is why the
     * loader records what it read.
     */
    public function testEditingAnIncludedFileInvalidates(): void
    {
        $included = $this->write('inc.yml', "global:\n  status_code: 401\n", 10);
        $main = $this->write('main.yml', "configs:\n  - " . $included . "\nglobal:\n  mode: block\n", 10);

        $this->assertSame(401, Config::load([$main])['global']['status_code'] ?? null);

        $this->write('inc.yml', "global:\n  status_code: 429\n");

        $this->assertSame(
            429,
            Config::load([$main])['global']['status_code'] ?? null,
            'A change to an included file must invalidate the cached merge'
        );
    }

    /**
     * Changing an environment variable invalidates.
     *
     * `%env()%` is resolved during the parse and baked into the merged result, so
     * a cached configuration would otherwise keep serving the value the variable
     * had when it was first read -- across a credential rotation, for instance.
     */
    public function testChangingTheEnvironmentInvalidates(): void
    {
        putenv('FW_CACHE_TEST_MODE=block');
        $_SERVER['FW_CACHE_TEST_MODE'] = 'block';

        $file = $this->write('env.yml', "global:\n  mode: '%env(FW_CACHE_TEST_MODE)%'\n", 10);

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);

        putenv('FW_CACHE_TEST_MODE=log');
        $_SERVER['FW_CACHE_TEST_MODE'] = 'log';

        $this->assertSame(
            'log',
            Config::load([$file])['global']['mode'] ?? null,
            'A changed environment variable must invalidate the cached merge'
        );

        putenv('FW_CACHE_TEST_MODE');
        unset($_SERVER['FW_CACHE_TEST_MODE']);
    }

    /**
     * Different overrides are different cache entries.
     */
    public function testOverridesAreNotSharedBetweenLoads(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        $blocking = Config::load([$file]);
        $logging = Config::load([$file], ['[global][mode]' => 'log']);

        $this->assertSame('block', $blocking['global']['mode'] ?? null);
        $this->assertSame('log', $logging['global']['mode'] ?? null);
    }

    /**
     * A load that reported problems is not cached.
     *
     * Otherwise a degraded result -- a file that could not be read, a remote
     * include served stale -- would be frozen in place, and the operator would
     * keep getting it long after fixing the cause.
     */
    public function testADegradedLoadIsNotCached(): void
    {
        $missing = $this->dir . '/not-here.yml';

        Config::clearLoadErrors();
        Config::load([$missing]);
        $this->assertNotEmpty(Config::getLoadErrors(), 'Precondition: the load reported a problem');

        // Now make the file exist. A cached failure would keep hiding it.
        $this->write('not-here.yml', "global:\n  mode: log\n");

        Config::clearLoadErrors();
        $this->assertSame(
            'log',
            Config::load([$missing])['global']['mode'] ?? null,
            'A failed load must not be cached'
        );
    }
}
