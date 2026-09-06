<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Plugins\Asn;
use Kanopi\Firewall\Plugins\Crs;
use Kanopi\Firewall\Plugins\GeoLocation;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Plugins\VulnerabilityScore;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * `metadata.name`, and what a plugin is called when it declares none.
 */
class PluginNamingTest extends AbstractTestCase
{
    /**
     * A declared name is what the plugin answers to.
     */
    public function testDeclaredNameIsUsed(): void
    {
        self::assertSame('office-network', (new IpAddress(['name' => 'office-network']))->getName());
    }

    /**
     * Two entries of one class are finally distinguishable.
     *
     * This is the whole point: four `IpAddress` rules used to log four
     * identical lines, and no query over them could say which fired.
     */
    public function testTwoEntriesOfOneClassCanBeToldApart(): void
    {
        $office = new IpAddress(['name' => 'office-network'], ['203.0.113.0/24']);
        $vendor = new IpAddress(['name' => 'uptime-robot'], ['198.51.100.0/24']);

        self::assertNotSame($office->getName(), $vendor->getName());
        self::assertSame('office-network', $office->getName());
        self::assertSame('uptime-robot', $vendor->getName());
    }

    /**
     * Surrounding whitespace is trimmed, since YAML makes it easy to add.
     */
    public function testDeclaredNameIsTrimmed(): void
    {
        self::assertSame('office', (new IpAddress(['name' => "  office\t"]))->getName());
    }

    /**
     * A name that says nothing falls back rather than logging an empty string.
     *
     * @param mixed $name
     *   The `metadata.name` value under test.
     */
    #[DataProvider('unusableNameProvider')]
    public function testUnusableNameFallsBackToTheClassName(mixed $name): void
    {
        self::assertSame('IP Address', (new IpAddress(['name' => $name]))->getName());
    }

    /**
     * Values that are not a usable name.
     *
     * @return array<string, array{mixed}>
     *   Provider sets, keyed by what makes each unusable.
     */
    public static function unusableNameProvider(): array
    {
        return [
            'empty string' => [''],
            'whitespace only' => ["  \t "],
            'null' => [null],
            'an array' => [['office']],
        ];
    }

    /**
     * Declaring no name keeps exactly the name the plugin always had.
     *
     * The compatibility promise this change rests on: no existing
     * configuration logs anything different than it did before.
     *
     * @param class-string<AbstractPluginBase> $class
     *   Plugin class under test.
     * @param string $expected
     *   The name it has always reported.
     */
    #[DataProvider('shippedPluginProvider')]
    public function testShippedPluginsKeepTheirNames(string $class, string $expected): void
    {
        // `[]`, not no arguments: `VulnerabilityScore` requires its metadata.
        self::assertSame($expected, (new $class([]))->getName());
    }

    /**
     * Every plugin this package ships, and the name it has always used.
     *
     * @return array<string, array{class-string<AbstractPluginBase>, string}>
     *   Provider sets, keyed by class name.
     */
    public static function shippedPluginProvider(): array
    {
        return [
            'IpAddress' => [IpAddress::class, 'IP Address'],
            'Url' => [Url::class, 'URL'],
            'UserAgent' => [UserAgent::class, 'User Agent'],
            'Asn' => [Asn::class, 'Autonomous System Network'],
            'GeoLocation' => [GeoLocation::class, 'GeoLocation'],
            'RateLimit' => [RateLimit::class, 'Rate Limit'],
            'VulnerabilityScore' => [VulnerabilityScore::class, 'VulnerabilityScore'],
            'AbuseIpdb' => [AbuseIpdb::class, 'AbuseIPDB'],
            'Crs' => [Crs::class, 'CRS'],
        ];
    }

    /**
     * Every shipped plugin also honours a declared name.
     *
     * @param class-string<AbstractPluginBase> $class
     *   Plugin class under test.
     */
    #[DataProvider('shippedPluginProvider')]
    public function testEveryShippedPluginHonoursADeclaredName(string $class): void
    {
        self::assertSame('named-rule', (new $class(['name' => 'named-rule']))->getName());
    }

    /**
     * A plugin outside this package that implements `getName()` still works.
     *
     * This is why `defaultName()` is concrete rather than abstract: making it
     * abstract would have left every such class fatally incomplete on upgrade,
     * and `getName()` is the shape the custom-plugin guide documented.
     */
    public function testAPluginThatImplementsGetNameItselfIsUnaffected(): void
    {
        $plugin = new class extends AbstractPluginBase {
            public function getName(): string
            {
                return 'Legacy Custom Plugin';
            }

            public function getDescription(): string
            {
                return '';
            }

            public function evaluate(Request $request): bool
            {
                return false;
            }
        };

        self::assertSame('Legacy Custom Plugin', $plugin->getName());
        self::assertSame('Legacy Custom Plugin', (new $plugin(['name' => 'ignored']))->getName());
    }

    /**
     * A plugin that overrides neither gets its short class name.
     */
    public function testAPluginThatOverridesNothingUsesItsClassName(): void
    {
        $plugin = new class extends AbstractPluginBase {
            public function getDescription(): string
            {
                return '';
            }

            public function evaluate(Request $request): bool
            {
                return false;
            }
        };

        // Anonymous classes carry a null byte and file path after the name;
        // what matters is that the namespace is gone and something usable is
        // left rather than a fully-qualified class string.
        self::assertStringNotContainsString('Kanopi\Firewall\Plugins', $plugin->getName());
        self::assertNotSame('', $plugin->getName());

        self::assertSame('declared', (new $plugin(['name' => 'declared']))->getName());
    }

    /**
     * `plugin_type` in a plugin's own log context names the concrete class.
     *
     * Pre-fix this was `self::class`, resolved in the abstract, so every
     * plugin reported `AbstractPluginBase` on any line it logged itself. With
     * names now configurable, the class is the only stable identifier a log
     * reader has left, so it has to be right.
     */
    public function testLoggingContextReportsTheConcreteClass(): void
    {
        $context = $this->loggingContext(new IpAddress(['name' => 'office-network']));

        self::assertSame(IpAddress::class, $context['plugin_type']);
        self::assertSame('office-network', $context['plugin_name']);
    }

    /**
     * And it does so for a plugin defined outside this package too.
     */
    public function testLoggingContextReportsTheConcreteClassForASubclass(): void
    {
        $plugin = new class extends IpAddress {
        };

        self::assertSame($plugin::class, $this->loggingContext($plugin)['plugin_type']);
    }

    /**
     * The stored block record carries the declared name too.
     *
     * `getStorageData()` reads the same accessor, so the `plugin` column on a
     * blocked client -- which is what an admin screen shows to explain the
     * block -- names the rule rather than its class.
     */
    public function testStoredBlockRecordCarriesTheDeclaredName(): void
    {
        $storage = new InMemoryStorage();
        $plugin = new IpAddress(['name' => 'known-bad-ranges'], ['198.51.100.0/24']);

        $data = $storage->getStorageData($this->getRequest('198.51.100.7'), $plugin);

        self::assertSame('known-bad-ranges', $data['plugin']);
    }

    /**
     * Read a plugin's protected logging context.
     *
     * @return array<string, mixed>
     *   The context the plugin contributes to every line it logs.
     */
    private function loggingContext(AbstractPluginBase $plugin): array
    {
        $method = new \ReflectionMethod($plugin, 'getLoggingContext');

        return $method->invoke($plugin);
    }
}
