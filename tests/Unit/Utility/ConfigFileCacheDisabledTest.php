<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Cache\RecordingCachePool;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * `KANOPI_FIREWALL_CONFIG_FILE_CACHE` (#447).
 *
 * Separate processes, because a constant cannot be undefined once set and
 * defining this one in the shared process would switch the file cache off for
 * every other test in the suite.
 */
class ConfigFileCacheDisabledTest extends AbstractTestCase
{
    private function cacheDir(): string
    {
        return defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) constant('KANOPI_FIREWALL_CACHE_DIR') . '/compiled'
            : sys_get_temp_dir() . '/kanopi-firewall-config';
    }

    private function write(string $contents): string
    {
        $path = sys_get_temp_dir() . '/fw-nofilecache-' . uniqid() . '.yml';
        file_put_contents($path, $contents);
        touch($path, time() - 10);

        return $path;
    }

    /**
     * False writes nothing, and every load still parses correctly.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testFalseDisablesTheFileCache(): void
    {
        define('KANOPI_FIREWALL_CONFIG_FILE_CACHE', false);

        $config = $this->write("global:\n  mode: block\n");
        $entry = $this->cacheDir() . '/' . hash('xxh128', serialize([$config])) . '.php';

        $this->assertSame('block', Config::load([$config])['global']['mode'] ?? null);
        $this->assertFileDoesNotExist($entry);

        file_put_contents($config, "global:\n  mode: log\n");
        $this->assertSame('log', Config::load([$config])['global']['mode'] ?? null);
        $this->assertFileDoesNotExist($entry);

        @unlink($config);
    }

    /**
     * A pool is still used with the file cache off.
     *
     * The constant is about files: a host that hands over a pool on the request
     * path and defines the constant for every other process gets both.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAPoolIsStillUsedWithTheFileCacheOff(): void
    {
        define('KANOPI_FIREWALL_CONFIG_FILE_CACHE', false);

        $pool = new RecordingCachePool();
        Config::setConfigCachePool($pool);

        $config = $this->write("global:\n  mode: block\n");
        Config::load([$config]);

        $this->assertCount(1, $pool->saved);

        Config::setConfigCachePool(null);
        @unlink($config);
    }

    /**
     * Any other value leaves the file cache on.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testTrueLeavesTheFileCacheOn(): void
    {
        define('KANOPI_FIREWALL_CONFIG_FILE_CACHE', true);

        $config = $this->write("global:\n  mode: block\n");
        $entry = $this->cacheDir() . '/' . hash('xxh128', serialize([$config])) . '.php';

        Config::load([$config]);
        $this->assertFileExists($entry);

        @unlink($entry);
        @unlink($config);
    }
}
