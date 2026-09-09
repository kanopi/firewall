<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;

/**
 * `KANOPI_FIREWALL_CACHE_MAX_AGE` (#271).
 *
 * Separate processes, because a constant cannot be undefined once set and
 * defining this one in the shared process would change the sweep for every
 * other test in the suite.
 */
class ConfigCacheMaxAgeTest extends AbstractTestCase
{
    /**
     * Where Config keeps compiled entries, resolved the way Config resolves it.
     */
    private function cacheDir(): string
    {
        return defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) constant('KANOPI_FIREWALL_CACHE_DIR') . '/compiled'
            : sys_get_temp_dir() . '/kanopi-firewall-config';
    }

    private function write(string $contents): string
    {
        $path = sys_get_temp_dir() . '/fw-maxage-' . uniqid() . '.yml';
        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * A shorter age sweeps entries the default would have kept.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testAShorterMaximumAgeIsHonoured(): void
    {
        define('KANOPI_FIREWALL_CACHE_MAX_AGE', 3600);

        $dir = $this->cacheDir();
        @mkdir($dir, 0700, true);

        $entry = $dir . '/two-hours-old.php';
        file_put_contents($entry, '<?php return [];');
        touch($entry, time() - 7200);

        $config = $this->write("global:\n  mode: block\n");
        Config::load([$config]);

        $this->assertFileDoesNotExist(
            $entry,
            'Two hours old is an orphan at a one-hour maximum, and would survive the 30-day default'
        );

        @unlink($config);
    }

    /**
     * Zero switches sweeping off.
     *
     * For a deployment that would rather manage the directory itself, or one
     * where the entries are on something the firewall should not be deleting
     * from.
     */
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testZeroDisablesSweeping(): void
    {
        define('KANOPI_FIREWALL_CACHE_MAX_AGE', 0);

        $dir = $this->cacheDir();
        @mkdir($dir, 0700, true);

        $entry = $dir . '/ancient.php';
        file_put_contents($entry, '<?php return [];');
        touch($entry, time() - (400 * 86400));

        $config = $this->write("global:\n  mode: block\n");
        Config::load([$config]);

        $this->assertFileExists($entry, 'Sweeping is off, so even a year-old entry stays');

        @unlink($entry);
        @unlink($config);
    }
}
