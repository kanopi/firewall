<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

require_once __DIR__ . '/../../Traits/UtilityNamespaceOverrides.php';

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

        // Config's error and warning buffers are static, and a load that
        // reported either is not cached. Without this, one test that
        // deliberately fails a load stops every test after it from caching
        // anything -- which quietly turns the rest into no-ops.
        Config::clearLoadErrors();
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
    /**
     * Where Config keeps compiled entries, resolved the way Config resolves it.
     *
     * Another test in the same process may have defined KANOPI_FIREWALL_CACHE_DIR,
     * which moves the directory. Assuming the default made earlier versions of
     * these tests pass while poisoning nothing.
     */
    private function cacheDir(): string
    {
        return defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) KANOPI_FIREWALL_CACHE_DIR . '/compiled'
            : sys_get_temp_dir() . '/kanopi-firewall-config';
    }

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

    /**
     * A cache file that raises on include is discarded, not fatal.
     *
     * The cache is PHP source, so a broken file does not merely fail to parse --
     * it raises inside the include, and `@` does not suppress that. Left alone it
     * would fatal on every subsequent request until somebody found and deleted
     * the file, turning a cache into an outage.
     */
    public function testAPoisonedCacheFileIsDiscardedAndRebuilt(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);
        Config::load([$file]);

        $poisoned = 0;

        foreach (glob($this->cacheDir() . '/*.php') ?: [] as $entry) {
            file_put_contents($entry, '<?php return \NoSuchClassAtAll::__set_state([]);');
            $poisoned++;
        }

        $this->assertGreaterThan(0, $poisoned, 'Precondition: something was cached');

        Config::clearLoadErrors();

        $this->assertSame(
            'block',
            Config::load([$file])['global']['mode'] ?? null,
            'A cache entry that raises must be discarded and the load redone'
        );
    }

    /**
     * A truncated or otherwise unrecognisable cache entry is discarded too.
     */
    public function testAnUnrecognisableCacheFileIsDiscarded(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);
        Config::load([$file]);

        foreach (glob($this->cacheDir() . '/*.php') ?: [] as $entry) {
            // Valid PHP, valid array, missing the keys the reader needs.
            file_put_contents($entry, '<?php return ["nothing" => "useful"];');
        }

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);
    }

    /**
     * A configuration holding an object is not cached.
     *
     * var_export() cannot represent one -- it emits __set_state(), which most
     * classes do not implement -- and serialize() is deliberately not used here,
     * to keep PHP deserialisation out of anything the library writes and reads
     * back. A configuration assembled in code can legitimately hold an object;
     * one parsed from YAML never can.
     */
    public function testAConfigurationContainingAnObjectIsNotCached(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        $before = count(glob($this->cacheDir() . '/*.php') ?: []);

        $result = Config::load([$file], ['[logger]' => new \stdClass()]);

        $after = count(glob($this->cacheDir() . '/*.php') ?: []);

        $this->assertInstanceOf(\stdClass::class, $result['logger'] ?? null, 'The object still reaches the caller');
        $this->assertSame($before, $after, 'Nothing containing an object should have been written');
    }

    /**
     * An inline array configuration reads no files, so there is nothing to
     * invalidate against and nothing is cached.
     */
    public function testAnInlineConfigurationIsNotCached(): void
    {
        $before = count(glob($this->cacheDir() . '/*.php') ?: []);

        $result = Config::load([['global' => ['mode' => 'log']]]);

        $after = count(glob($this->cacheDir() . '/*.php') ?: []);

        $this->assertSame('log', $result['global']['mode'] ?? null);
        $this->assertSame($before, $after);
    }

    /**
     * A cache directory that is not writable disables the cache, quietly.
     *
     * The configuration still loads -- it just parses every time. A cache that
     * cannot be written is a performance problem, not a correctness one, and it
     * must not stop the firewall starting.
     */
    public function testAnUnwritableCacheDirectoryDisablesTheCache(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        $GLOBALS['simulate_utility_is_writable_failure'] = true;

        try {
            $result = Config::load([$file]);
        } finally {
            $GLOBALS['simulate_utility_is_writable_failure'] = false;
        }

        $this->assertSame('block', $result['global']['mode'] ?? null);
    }

    /**
     * A publish that fails leaves no temporary behind and no cache entry.
     */
    public function testAFailedPublishLeavesNoTemporaryBehind(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        $dir = $this->cacheDir();
        $GLOBALS['simulate_utility_rename_failure'] = true;

        try {
            $result = Config::load([$file]);
        } finally {
            $GLOBALS['simulate_utility_rename_failure'] = false;
        }

        $this->assertSame('block', $result['global']['mode'] ?? null);
        $this->assertSame([], glob($dir . '/*.tmp') ?: [], 'A failed publish should clean up after itself');
    }

    /**
     * A cache file that cannot be written is not an error either.
     */
    public function testAnUnwritableCacheFileIsSurvivable(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: log\n", 10);

        $GLOBALS['simulate_utility_file_put_contents_failure'] = true;

        try {
            $result = Config::load([$file]);
        } finally {
            $GLOBALS['simulate_utility_file_put_contents_failure'] = false;
        }

        $this->assertSame('log', $result['global']['mode'] ?? null);
    }

    /**
     * A cache directory that cannot be created disables the cache.
     */
    public function testACacheDirectoryThatCannotBeCreatedDisablesTheCache(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n", 10);

        // is_dir() false throughout, and mkdir() on a directory that already
        // exists fails -- so the create path is taken and still comes up empty.
        $GLOBALS['simulate_utility_is_dir_failure'] = true;

        try {
            $result = Config::load([$file]);
        } finally {
            $GLOBALS['simulate_utility_is_dir_failure'] = false;
        }

        $this->assertSame('block', $result['global']['mode'] ?? null);
    }

    /**
     * A remote include whose refresh cannot be claimed serves its cached copy.
     *
     * The single-flight guard from #228: one process refreshes, the rest use what
     * they have rather than queueing behind a fetch they do not need to make.
     */
    public function testARefreshItCannotClaimServesTheCachedCopy(): void
    {
        $url = 'https://single-flight-test.invalid/config.yml';

        // Where fileGetContents() keeps remote copies, resolved its way.
        $cacheDir = defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) KANOPI_FIREWALL_CACHE_DIR
            : '/tmp/cache';

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0775, true);
        }

        $cacheFile = $cacheDir . '/' . md5($url) . '.cache';
        file_put_contents($cacheFile, "global:\n  mode: log\n");
        touch($cacheFile, time() - 7200); // stale, so a refresh is attempted

        // Another process already holds the claim.
        $GLOBALS['simulate_utility_flock_failure'] = true;

        try {
            Config::clearLoadErrors();
            $result = Config::load([$url]);
        } finally {
            $GLOBALS['simulate_utility_flock_failure'] = false;
            @unlink($cacheFile);
            @unlink($cacheFile . '.refresh');
        }

        $this->assertSame('log', $result['global']['mode'] ?? null);
    }

    /**
     * Where fileGetContents() keeps remote copies, resolved its way.
     */
    private function remoteCacheDir(): string
    {
        $dir = defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) KANOPI_FIREWALL_CACHE_DIR
            : '/tmp/cache';

        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        return $dir;
    }

    /**
     * A refresh claim that cannot even be opened does not stop the fetch.
     *
     * With nothing cached to fall back on, the caller needs the content more
     * than it needs the politeness -- so it fetches anyway.
     */
    public function testARefreshClaimThatCannotBeOpenedStillFetches(): void
    {
        $url = 'https://claim-open-fail.invalid/config.yml';

        $GLOBALS['simulate_utility_fopen_failure'] = true;
        $GLOBALS['utility_file_get_contents_return'] = "global:\n  mode: exception\n";

        try {
            Config::clearLoadErrors();
            $result = Config::load([$url]);
        } finally {
            $GLOBALS['simulate_utility_fopen_failure'] = false;
            $GLOBALS['utility_file_get_contents_return'] = null;
            @unlink($this->remoteCacheDir() . '/' . md5($url) . '.cache');
        }

        $this->assertSame('exception', $result['global']['mode'] ?? null);
    }

    /**
     * A remote copy that cannot be written still serves the content it fetched.
     *
     * Failing to cache is a performance problem; failing to return the rules is
     * a correctness one.
     */
    public function testAnUnwritableRemoteCacheStillServesTheFetch(): void
    {
        $url = 'https://remote-write-fail.invalid/config.yml';

        $GLOBALS['utility_file_get_contents_return'] = "global:\n  mode: log\n";
        $GLOBALS['simulate_utility_file_put_contents_failure'] = true;

        try {
            Config::clearLoadErrors();
            $result = Config::load([$url]);
        } finally {
            $GLOBALS['utility_file_get_contents_return'] = null;
            $GLOBALS['simulate_utility_file_put_contents_failure'] = false;
            @unlink($this->remoteCacheDir() . '/' . md5($url) . '.cache');
        }

        $this->assertSame('log', $result['global']['mode'] ?? null);
    }

    /**
     * A remote copy that cannot be published leaves no temporary behind.
     */
    public function testAnUnpublishableRemoteCacheCleansUp(): void
    {
        $url = 'https://remote-publish-fail.invalid/config.yml';
        $dir = $this->remoteCacheDir();

        $GLOBALS['utility_file_get_contents_return'] = "global:\n  mode: block\n";
        $GLOBALS['simulate_utility_rename_failure'] = true;

        try {
            Config::clearLoadErrors();
            $result = Config::load([$url]);
        } finally {
            $GLOBALS['utility_file_get_contents_return'] = null;
            $GLOBALS['simulate_utility_rename_failure'] = false;
            @unlink($dir . '/' . md5($url) . '.cache');
        }

        $this->assertSame('block', $result['global']['mode'] ?? null);
        $this->assertSame([], glob($dir . '/' . md5($url) . '.cache.*.tmp') ?: []);
    }
}
