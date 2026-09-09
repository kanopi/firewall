<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\StarterConfig;

/**
 * The starting configuration `bin/firewall-init` writes (#210).
 *
 * The test that matters is the last one: every combination it can produce must
 * actually load. A generator whose output does not parse is worse than no
 * generator, because the person running it has no reason to suspect the file
 * rather than themselves.
 */
class StarterConfigTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-starter-' . uniqid();
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
     * Write a rendered config and load it back.
     *
     * @return array<string, mixed>
     *   The loaded configuration.
     */
    private function load(string $yaml): array
    {
        $path = $this->dir . '/firewall.yml';
        file_put_contents($path, $yaml);

        Config::clearLoadErrors();
        $config = Config::load([$path]);

        $this->assertSame([], Config::getLoadErrors(), 'A generated config must load without errors');

        return $config;
    }

    /**
     * Every combination the generator can produce loads, and carries rules.
     *
     * 90 of them. Written as one test rather than a data provider because the
     * point is the *matrix* -- a combination that fails is a combination
     * somebody will pick, and naming which one failed is enough.
     */
    public function testEveryCombinationLoadsAndBringsRules(): void
    {
        $choices = StarterConfig::choices();
        $checked = 0;

        foreach ($choices['platform'] as $platform) {
            foreach ($choices['cdn'] as $cdn) {
                foreach ($choices['storage'] as $storage) {
                    foreach ($choices['mode'] as $mode) {
                        $where = sprintf('%s / %s / %s / %s', $platform, $cdn, $storage, $mode);
                        $config = $this->load(StarterConfig::render($platform, $cdn, $storage, $mode));

                        $this->assertSame($mode, $config['global']['mode'] ?? null, $where);
                        $this->assertNotSame([], $config['plugins'] ?? [], $where . ': presets brought no rules');
                        $this->assertIsArray($config['storage'] ?? null, $where . ': no storage configured');

                        $checked++;
                    }
                }
            }
        }

        $this->assertSame(90, $checked, 'Every combination was checked');
    }

    /**
     * Observe mode is the default, and says why.
     *
     * Turning an unfamiliar rule set straight on is how a site finds its false
     * positives in production, and the usual recovery is to remove the firewall.
     */
    public function testObserveModeExplainsItself(): void
    {
        $yaml = StarterConfig::render('other', 'none', 'file', 'log');

        $this->assertSame('log', $this->load($yaml)['global']['mode'] ?? null);
        $this->assertStringContainsString('Observing, not enforcing', $yaml);
        $this->assertStringContainsString('Change to `block`', $yaml);
    }

    /**
     * Enforcing mode says how to back out of it.
     */
    public function testEnforcingModeMentionsObserving(): void
    {
        $yaml = StarterConfig::render('other', 'none', 'file', 'block');

        $this->assertSame('block', $this->load($yaml)['global']['mode'] ?? null);
        $this->assertStringContainsString('mode: log', $yaml);
    }

    /**
     * A platform gets its own preset, and everyone gets the shared ones.
     */
    public function testPlatformPresetsAreIncluded(): void
    {
        $this->assertStringContainsString('wordpress.yml', StarterConfig::render('wordpress', 'none', 'file', 'log'));
        $this->assertStringContainsString('drupal.yml', StarterConfig::render('drupal', 'none', 'file', 'log'));

        $other = StarterConfig::render('other', 'none', 'file', 'log');
        $this->assertStringNotContainsString('wordpress.yml', $other);
        $this->assertStringContainsString('malicious-requests.yml', $other, 'The documented starting point is always in');
    }

    /**
     * Presets are referenced portably.
     *
     * `presets/…` only works when the config sits beside a presets directory.
     * A generated file has no idea where vendor/ is.
     */
    public function testPresetsAreReferencedByToken(): void
    {
        $this->assertStringContainsString('{presets_dir}/', StarterConfig::render('drupal', 'none', 'file', 'log'));
    }

    /**
     * A CDN is asserted, and the ranges are pointed at rather than baked in.
     */
    public function testACdnIsAssertedAndItsRangesArePointedAt(): void
    {
        $yaml = StarterConfig::render('other', 'cloudflare', 'file', 'log');
        $config = $this->load($yaml);

        $this->assertTrue($config['global']['behind_proxy'] ?? null);
        $this->assertStringContainsString('cloudflare.com/ips', $yaml, 'It says where the current ranges live');
        $this->assertStringContainsString('setTrustedProxies', $yaml, 'And that they go in PHP, not YAML');
    }

    /**
     * The generated file works before the proxies are declared.
     *
     * `require_trusted_proxies: true` would make the firewall refuse to start
     * until somebody adds the PHP — and a generator whose output does not boot
     * gets deleted rather than fixed. It ships false, with `behind_proxy: true`
     * making the gap loud on every startup.
     */
    public function testTrustedProxiesAreNotRequiredOutOfTheBox(): void
    {
        $config = $this->load(StarterConfig::render('other', 'pantheon', 'file', 'log'));

        $this->assertFalse($config['global']['require_trusted_proxies'] ?? null);
        $this->assertTrue($config['global']['behind_proxy'] ?? null, 'The fact is still asserted, so it is still reported');
    }

    /**
     * With nothing in front, the assertion says so.
     */
    public function testNoCdnAssertsNoProxy(): void
    {
        $config = $this->load(StarterConfig::render('other', 'none', 'file', 'log'));

        $this->assertFalse($config['global']['behind_proxy'] ?? null);
    }

    /**
     * Each storage choice writes its own backend, and resolves without env vars.
     *
     * The defaults are placeholders so the file loads before anything is
     * configured — `bin/firewall-doctor` reporting an unreachable database is a
     * better first failure than a config that will not parse.
     */
    public function testEachStorageBackendResolvesWithoutEnvironmentVariables(): void
    {
        $expected = [
            'file' => 'FileStorage',
            'database' => 'DatabaseStorage',
            'redis' => 'RedisStorage',
        ];

        foreach ($expected as $storage => $class) {
            $config = $this->load(StarterConfig::render('other', 'none', $storage, 'log'));

            $this->assertStringContainsString(
                $class,
                (string) ($config['storage']['type'] ?? ''),
                $storage . ' did not select ' . $class
            );
        }
    }

    /**
     * The file backend defaults somewhere that exists.
     *
     * It pointed at /tmp/firewall/, a directory nothing creates, so a freshly
     * generated config failed `firewall-doctor` on its first run.
     */
    public function testTheDefaultStoragePathIsInADirectoryThatExists(): void
    {
        $config = $this->load(StarterConfig::render('other', 'none', 'file', 'log'));
        $path = (string) ($config['storage']['config']['storage_file'] ?? '');

        $this->assertNotSame('', $path);
        $this->assertDirectoryExists(dirname($path), 'A generated config must work before anything is created');
    }

    /**
     * An unknown platform falls back rather than producing nothing.
     */
    public function testAnUnknownPlatformFallsBackToTheSharedPresets(): void
    {
        $yaml = StarterConfig::render('joomla', 'none', 'file', 'log');

        $this->assertStringContainsString('malicious-requests.yml', $yaml);
        $this->assertNotSame([], $this->load($yaml)['plugins'] ?? []);
    }

    /**
     * An unknown CDN is treated as none rather than emitting a broken block.
     */
    public function testAnUnknownCdnIsTreatedAsNone(): void
    {
        $config = $this->load(StarterConfig::render('other', 'akamai', 'file', 'log'));

        $this->assertFalse($config['global']['behind_proxy'] ?? null);
    }

    /**
     * An unknown storage falls back to the file backend.
     */
    public function testAnUnknownStorageFallsBackToFile(): void
    {
        $config = $this->load(StarterConfig::render('other', 'none', 'memcached', 'log'));

        $this->assertStringContainsString('FileStorage', (string) ($config['storage']['type'] ?? ''));
    }
}
