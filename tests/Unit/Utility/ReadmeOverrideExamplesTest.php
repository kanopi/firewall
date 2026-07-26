<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Utility\Config;
use Monolog\Handler\TestHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Verifies that every override example documented in README.md actually
 * lands in the merged configuration.
 *
 * `Firewall::create()` always prepends `config/config.yml`, which ships
 * `global: ~`, `storage: ~`, `logger: ~`, `bypass: ~` and `block: ~` — all
 * NULL. PropertyAccess cannot traverse into NULL and `Config::load()` catches
 * the resulting exception, so a broken override is indistinguishable from a
 * working one at the call site: no return value, no exception, no log entry.
 * That is exactly how the README came to document an override example that
 * silently did nothing (issue #82).
 *
 * These tests therefore load through the real `config/config.yml`, the same
 * way `Firewall::create()` does, and assert the overridden value is readable
 * back out afterwards. Asserting only that `Config::load()` returns an array
 * would pass against the broken behavior.
 *
 * When adding or changing an override example in README.md, mirror it here.
 */
final class ReadmeOverrideExamplesTest extends TestCase
{
    /**
     * Path to the default config the firewall always loads first.
     */
    private const DEFAULT_CONFIG = __DIR__ . '/../../../config/config.yml';

    /**
     * Override paths documented in README.md, each with a representative value.
     *
     * @return array<string, array{0: string, 1: mixed}>
     */
    public static function readmeOverrideProvider(): array
    {
        return [
            // "Dynamic Configuration Overrides"
            'storage location' => ['[storage][config][file]', '/tmp/firewall.data'],
            'geoip db on a plugins: entry' => ['[plugins][1][metadata][reader][db]', '/tmp/GeoLite2-City.mmdb'],
            'redis host on a plugins: entry' => ['[plugins][3][metadata][storage][config][redis][host]', 'localhost'],
            'disable a plugins: entry' => ['[plugins][2][enable]', false],

            // "Requiring the config to load" (#78) — the override form is the
            // route that still works when the config file carrying the flag
            // is the one that failed to load.
            'require config' => ['[global][require_config]', true],

            // "Dynamic Configuration Overrides" — legacy block:/bypass: format.
            'legacy geoip db' => ['[block][\Kanopi\Firewall\Plugins\GeoLocation][metadata][reader][db]', '/tmp/GeoLite2-City.mmdb'],
            'legacy disable plugin' => ['[block][\Kanopi\Firewall\Plugins\UserAgent][enable]', false],
        ];
    }

    /**
     * Every documented override path must survive the merge.
     */
    #[DataProvider('readmeOverrideProvider')]
    public function testReadmeOverrideLands(string $path, mixed $value): void
    {
        $config = Config::load([self::DEFAULT_CONFIG], [$path => $value]);

        self::assertSame(
            $value,
            PropertyAccess::createPropertyAccessor()->getValue($config, $path),
            sprintf('README documents the override path "%s", but it did not land in the merged config.', $path)
        );
    }

    /**
     * "Injecting Your Own Logger" — Option 1 passes an instantiated Monolog
     * handler through the override mechanism. `logger: ~` in the default
     * config used to make this a silent no-op.
     */
    public function testReadmeLoggerHandlerInjectionLands(): void
    {
        $handler = new TestHandler();

        $config = Config::load([self::DEFAULT_CONFIG], ['[logger][0][class]' => $handler]);

        self::assertSame($handler, $config['logger'][0]['class']);
    }

    /**
     * A user config layered on top must not change the outcome — the override
     * has to land whether or not the caller's own YAML defines the section.
     */
    public function testReadmeOverrideLandsOverUserSuppliedConfig(): void
    {
        $userConfig = ['plugins' => [['type' => 'ip', 'response' => 'block', 'values' => ['1.2.3.4']]]];

        $config = Config::load([self::DEFAULT_CONFIG, $userConfig], ['[storage][config][file]' => '/tmp/firewall.data']);

        self::assertSame('/tmp/firewall.data', $config['storage']['config']['file']);
        self::assertSame('ip', $config['plugins'][0]['type']);
    }

    /**
     * Opening NULL sections must not clobber values that are actually set.
     */
    public function testOverrideDoesNotDiscardSiblingConfiguration(): void
    {
        $userConfig = ['storage' => ['class' => 'Kanopi\Firewall\Storage\FileStorage', 'config' => ['ttl' => 3600]]];

        $config = Config::load([self::DEFAULT_CONFIG, $userConfig], ['[storage][config][file]' => '/tmp/firewall.data']);

        self::assertSame('/tmp/firewall.data', $config['storage']['config']['file']);
        self::assertSame(3600, $config['storage']['config']['ttl']);
        self::assertSame('Kanopi\Firewall\Storage\FileStorage', $config['storage']['class']);
    }

    /**
     * A scalar sitting where the path needs to traverse is a genuine caller
     * error. It stays swallowed rather than silently destroying that value.
     */
    public function testOverrideThroughScalarNodeIsIgnoredAndPreservesValue(): void
    {
        $config = Config::load([['storage' => 'not-an-array']], ['[storage][config][file]' => '/tmp/firewall.data']);

        self::assertSame('not-an-array', $config['storage']);
    }
}
