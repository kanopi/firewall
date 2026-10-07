<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;

/**
 * Separate configs combine lists the way `configs:` includes do (#481).
 *
 * `Firewall::create([$a, $b])` merged its sources with `NestedArray::mergeDeepArray()`,
 * which appends lists at every depth. A second config could neither replace
 * `trusted_proxies` -- both lists were trusted -- nor clear `lockdown_allow`. Includes had
 * replaced lists all along, and since #476 an empty one clears. Now both agree.
 */
class ConfigSeparateSourcesTest extends AbstractTestCase
{
    private const URL = 'Kanopi\\Firewall\\Plugins\\Url';

    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-config-sources-' . uniqid();
        mkdir($this->dir, 0700, true);
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

    public function testALaterListReplacesAnEarlierOne(): void
    {
        $config = Config::load([
            ['global' => ['trusted_proxies' => ['10.0.0.0/8']]],
            ['global' => ['trusted_proxies' => ['192.168.0.0/16']]],
        ]);

        // Was ['10.0.0.0/8', '192.168.0.0/16']: both trusted.
        $this->assertSame(['192.168.0.0/16'], $config['global']['trusted_proxies']);
    }

    public function testAnEmptyListClearsOne(): void
    {
        $config = Config::load([
            ['global' => ['lockdown_allow' => ['203.0.113.5', '198.51.100.0/24']]],
            ['global' => ['lockdown_allow' => []]],
        ]);

        // Was ['203.0.113.5', '198.51.100.0/24']: the allowlist stayed in force.
        $this->assertSame([], $config['global']['lockdown_allow']);
    }

    public function testAListOfMapsIsReplacedWhole(): void
    {
        $config = Config::load([
            ['global' => ['blocking_escalation' => [['window' => 300, 'offense' => 0], ['window' => 3600, 'offense' => 1]]]],
            ['global' => ['blocking_escalation' => [['window' => 60, 'offense' => 0]]]],
        ]);

        $this->assertSame([['window' => 60, 'offense' => 0]], $config['global']['blocking_escalation']);
    }

    public function testRootPluginsAppend(): void
    {
        $config = Config::load([
            ['plugins' => [['plugin' => 'A']]],
            ['plugins' => [['plugin' => 'B']]],
            ['plugins' => []],
        ]);

        $this->assertSame([['plugin' => 'A'], ['plugin' => 'B']], $config['plugins']);
    }

    public function testALegacyRulesConfigAppends(): void
    {
        $config = Config::load([
            ['block' => [self::URL => ['config' => ['path:/admin']]]],
            ['bypass' => [self::URL => ['config' => ['path:/health']]], 'block' => [self::URL => ['config' => ['path:/login']]]],
            ['bypass' => [self::URL => ['config' => ['path:/status']]]],
        ]);

        $this->assertSame(['path:/admin', 'path:/login'], $config['block'][self::URL]['config']);
        $this->assertSame(['path:/health', 'path:/status'], $config['bypass'][self::URL]['config']);
    }

    public function testOtherListsInsideALegacyRuleAreReplaced(): void
    {
        $config = Config::load([
            ['block' => [self::URL => ['metadata' => ['verify_suffixes' => ['.googlebot.com', '.google.com']]]]],
            ['block' => [self::URL => ['metadata' => ['verify_suffixes' => ['.bing.com']]]]],
        ]);

        $this->assertSame(['.bing.com'], $config['block'][self::URL]['metadata']['verify_suffixes']);
    }

    public function testALaterLegacyPriorityAndEnableStillWin(): void
    {
        $config = Config::load([
            ['block' => [self::URL => ['priority' => 0, 'enable' => true, 'config' => ['path:/admin']]]],
            ['block' => [self::URL => ['priority' => -10, 'enable' => false]]],
        ]);

        // Unchanged: unlike includes, a later source can still switch a rule off.
        $this->assertSame(-10, $config['block'][self::URL]['priority']);
        $this->assertFalse($config['block'][self::URL]['enable']);
    }

    public function testMapsStillMergeAndScalarsStillWin(): void
    {
        $config = Config::load([
            ['global' => ['mode' => 'log', 'block_page' => ['title' => 'Blocked', 'lang' => 'en'], 'panic_file' => ['x']]],
            ['global' => ['mode' => 'block', 'block_page' => ['title' => 'Refused'], 'panic_file' => '/run/panic', 'trusted_proxies' => ['10.0.0.0/8']]],
        ]);

        $this->assertSame('block', $config['global']['mode']);
        $this->assertSame(['title' => 'Refused', 'lang' => 'en'], $config['global']['block_page']);
        $this->assertSame('/run/panic', $config['global']['panic_file']);
        $this->assertSame(['10.0.0.0/8'], $config['global']['trusted_proxies']);
    }

    public function testAListOverAMapAddsItsEntriesAsBefore(): void
    {
        $config = Config::load([
            ['global' => ['block_page' => ['title' => 'Blocked']]],
            ['global' => ['block_page' => ['a', 'b']]],
        ]);

        $this->assertSame(['title' => 'Blocked', 0 => 'a', 1 => 'b'], $config['global']['block_page']);
    }

    /**
     * An entry cached before #481 was merged by the old rules, and its files still match.
     * Served, it would keep both proxy lists until a file changed.
     */
    public function testAnEntryCachedByAnEarlierReleaseIsReparsed(): void
    {
        $base = $this->dir . '/base.yml';
        $site = $this->dir . '/site.yml';
        file_put_contents($base, "global:\n  trusted_proxies: [10.0.0.0/8]\n");
        file_put_contents($site, "global:\n  trusted_proxies: [192.168.0.0/16]\n");
        touch($base, time() - 10);
        touch($site, time() - 10);

        Config::load([$base, $site]);

        $cacheDir = defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) constant('KANOPI_FIREWALL_CACHE_DIR') . '/compiled'
            : sys_get_temp_dir() . '/kanopi-firewall-config';
        $entry = $cacheDir . '/' . hash('xxh128', serialize([$base, $site])) . '.php';
        $this->assertFileExists($entry);

        // Rewrite it as an earlier release left it: no format, and the old merge's result.
        $payload = require $entry;
        $this->assertSame(2, $payload['format']);
        unset($payload['format']);
        $payload['config']['global']['trusted_proxies'] = ['10.0.0.0/8', '192.168.0.0/16'];
        file_put_contents($entry, '<?php return ' . var_export($payload, true) . ';');

        try {
            $this->assertSame(['192.168.0.0/16'], Config::load([$base, $site])['global']['trusted_proxies']);
        } finally {
            @unlink($entry);
        }
    }

    public function testFilesMergeTheSameWayAsArrays(): void
    {
        $base = $this->dir . '/base.yml';
        $site = $this->dir . '/site.yml';
        file_put_contents($base, "global:\n  trusted_proxies: [10.0.0.0/8]\n");
        file_put_contents($site, "global:\n  trusted_proxies: [192.168.0.0/16]\n");

        $this->assertSame(['192.168.0.0/16'], Config::load([$base, $site])['global']['trusted_proxies']);
    }
}
