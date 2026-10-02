<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Cache\RecordingCachePool;
use Kanopi\Firewall\Tests\Cache\ThrowingOnGetCachePool;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;

/**
 * The compiled-configuration cache kept in a PSR-6 pool (#447).
 *
 * The pool is process-wide, so every test hands it back in tearDown();
 * otherwise the file-cache tests after this class would run against a pool.
 */
class ConfigCachePoolTest extends AbstractTestCase
{
    private string $dir;

    private RecordingCachePool $pool;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-config-pool-test-' . uniqid();
        mkdir($this->dir, 0700, true);

        // A load that reported an error is not cached; see ConfigCacheTest.
        Config::clearLoadErrors();

        $this->pool = new RecordingCachePool();
        Config::setConfigCachePool($this->pool);
    }

    protected function tearDown(): void
    {
        Config::setConfigCachePool(null);

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        parent::tearDown();
    }

    /**
     * Where Config keeps compiled files, resolved the way Config resolves it.
     */
    private function cacheDir(): string
    {
        return defined('KANOPI_FIREWALL_CACHE_DIR')
            ? (string) constant('KANOPI_FIREWALL_CACHE_DIR') . '/compiled'
            : sys_get_temp_dir() . '/kanopi-firewall-config';
    }

    /**
     * The key Config uses, for the file entry and (prefixed) the pool entry.
     *
     * @param array<int, string> $configs
     *   What was loaded.
     */
    private function key(array $configs): string
    {
        return hash('xxh128', serialize($configs));
    }

    private function write(string $name, string $contents, int $ageSeconds = 10): string
    {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, $contents);
        touch($path, time() - $ageSeconds);

        return $path;
    }

    /**
     * A load is stored in the pool, and no file is written.
     */
    public function testALoadIsStoredInThePoolAndNotOnDisk(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");
        $key = $this->key([$file]);

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);

        $this->assertSame(['kanopi_firewall_config.' . $key], $this->pool->saved);
        $this->assertFileDoesNotExist($this->cacheDir() . '/' . $key . '.php', 'A pool replaces the file, it does not add to it');
    }

    /**
     * A second load is served from the pool, without a parse.
     *
     * The stored merge is replaced with one the file could not have produced, so
     * getting it back means nothing was parsed.
     */
    public function testAHitIsServedFromThePool(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");
        Config::load([$file]);

        $poolKey = 'kanopi_firewall_config.' . $this->key([$file]);
        $entry = $this->pool->values[$poolKey];
        $this->assertIsArray($entry);
        $entry['config'] = ['global' => ['mode' => 'from-the-pool']];
        $this->pool->values[$poolKey] = $entry;

        $this->assertSame('from-the-pool', Config::load([$file])['global']['mode'] ?? null);
        $this->assertCount(1, $this->pool->saved, 'A hit writes nothing');
    }

    /**
     * Editing a file invalidates a pooled entry, as it does a file entry.
     */
    public function testEditingTheFileInvalidatesAPooledEntry(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");
        Config::load([$file]);

        $this->write('main.yml', "global:\n  mode: log\n", 0);

        $this->assertSame('log', Config::load([$file])['global']['mode'] ?? null);
        $this->assertCount(2, $this->pool->saved, 'The fresh merge replaces the stale one');
    }

    /**
     * Changing the environment invalidates a pooled entry.
     */
    public function testChangingTheEnvironmentInvalidatesAPooledEntry(): void
    {
        putenv('FW_POOL_TEST_MODE=block');
        $_SERVER['FW_POOL_TEST_MODE'] = 'block';

        $file = $this->write('env.yml', "global:\n  mode: '%env(FW_POOL_TEST_MODE)%'\n");

        try {
            $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);

            putenv('FW_POOL_TEST_MODE=log');
            $_SERVER['FW_POOL_TEST_MODE'] = 'log';

            $this->assertSame('log', Config::load([$file])['global']['mode'] ?? null);
        } finally {
            putenv('FW_POOL_TEST_MODE');
            unset($_SERVER['FW_POOL_TEST_MODE']);
        }
    }

    /**
     * A malformed entry is ignored, deleted, and replaced by a real load.
     *
     * @param mixed $entry
     *   What the pool holds.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('malformedEntries')]
    public function testAMalformedEntryIsIgnored(mixed $entry): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");
        $poolKey = 'kanopi_firewall_config.' . $this->key([$file]);
        $this->pool->values[$poolKey] = $entry;

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);
        $this->assertSame([$poolKey], $this->pool->deleted);
        $this->assertSame([$poolKey], $this->pool->saved);
    }

    /**
     * @return array<string, array{mixed}>
     *   Entries that are not a payload.
     */
    public static function malformedEntries(): array
    {
        return [
            'a string' => ['not a payload'],
            'missing keys' => [['config' => ['global' => ['mode' => 'log']]]],
            'files not a list' => [['config' => [], 'files' => 'x', 'env' => 'y']],
        ];
    }

    /**
     * A malformed entry that cannot be deleted is still only ignored.
     */
    public function testAMalformedEntryThatCannotBeDeletedIsIgnored(): void
    {
        $this->pool->throwOnDelete = true;

        $file = $this->write('main.yml', "global:\n  mode: block\n");
        $poolKey = 'kanopi_firewall_config.' . $this->key([$file]);
        $this->pool->values[$poolKey] = 'not a payload';

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);
        $this->assertSame([$poolKey], $this->pool->saved, 'The real load still replaces it');
    }

    /**
     * A pool that throws costs a parse, never the load.
     */
    public function testAPoolThatThrowsFallsBackToAParse(): void
    {
        Config::setConfigCachePool(new ThrowingOnGetCachePool());

        $file = $this->write('main.yml', "global:\n  mode: block\n");

        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);
        $this->assertSame('block', Config::load([$file])['global']['mode'] ?? null);
        $this->assertFileDoesNotExist(
            $this->cacheDir() . '/' . $this->key([$file]) . '.php',
            'A failing pool does not fall back to writing files'
        );
    }

    /**
     * Entries expire after the maximum age, standing in for the sweep.
     */
    public function testAnEntryExpiresAfterTheMaximumAge(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");
        Config::load([$file]);

        $this->assertSame(
            ['kanopi_firewall_config.' . $this->key([$file]) => 30 * 86400],
            $this->pool->lifetimes
        );
    }

    /**
     * A configuration holding an object is not pooled either.
     *
     * The guard exists to keep anything but arrays and scalars out of what is
     * written and read back; a pool must not become the way around it.
     */
    public function testAConfigurationContainingAnObjectIsNotPooled(): void
    {
        $file = $this->write('main.yml', "global:\n  mode: block\n");

        $result = Config::load([$file, ['logger' => new \stdClass()]]);

        $this->assertInstanceOf(\stdClass::class, $result['logger'] ?? null);
        $this->assertSame([], $this->pool->saved);
    }

    /**
     * Setting null goes back to the file cache.
     */
    public function testClearingThePoolGoesBackToFiles(): void
    {
        Config::setConfigCachePool(null);

        $file = $this->write('main.yml', "global:\n  mode: block\n");
        Config::load([$file]);

        $entry = $this->cacheDir() . '/' . $this->key([$file]) . '.php';
        $this->assertFileExists($entry);
        $this->assertSame([], $this->pool->saved);

        @unlink($entry);
    }
}
