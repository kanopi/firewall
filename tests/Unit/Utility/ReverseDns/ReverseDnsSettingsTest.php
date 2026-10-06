<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\NoOptionsResolver;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\OptionalArgumentResolver;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ScriptedResolver;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ThrowingConstructorResolver;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\UnbuildableResolver;
use Kanopi\Firewall\Utility\ReverseDns\BuiltinProviders;
use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDns\SystemResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Which resolver each verifying rule uses, and the rules the configuration follows (#473).
 */
class ReverseDnsSettingsTest extends TestCase
{
    private const INTERNAL_ENDPOINT = 'https://resolver.internal/dns-query?name={{ dns.name }}&type={{ dns.type }}';

    protected function setUp(): void
    {
        parent::setUp();
        ReverseDnsSettings::reset();
        ScriptedResolver::reset();
    }

    protected function tearDown(): void
    {
        ReverseDnsSettings::reset();
        ScriptedResolver::reset();
        parent::tearDown();
    }

    /**
     * @param array<string, mixed> $reverseDns
     */
    private function settings(array $reverseDns): ReverseDnsSettings
    {
        return ReverseDnsSettings::fromGlobal(['reverse_dns' => $reverseDns]);
    }

    public function testNothingConfiguredMeansTheVerifiersOwnLookups(): void
    {
        $this->assertNull(ReverseDnsSettings::current()->resolverFor([]));
        $this->assertSame(250.0, ReverseDnsSettings::current()->slowThresholdFor([]));
        $this->assertSame(
            ['resolver' => SystemResolver::class, 'provider' => null, 'endpoint' => null, 'address' => null],
            ReverseDnsSettings::current()->describeFor([])
        );
    }

    public function testAGlobalProviderIsEveryRulesDefault(): void
    {
        $settings = $this->settings(['provider' => 'cloudflare']);

        $this->assertInstanceOf(DnsOverHttpResolver::class, $settings->resolverFor([]));
        $this->assertSame(
            ['resolver' => DnsOverHttpResolver::class, 'provider' => 'cloudflare', 'endpoint' => 'cloudflare-dns.com', 'address' => '1.1.1.1'],
            $settings->describeFor([])
        );
    }

    public function testARuleCanPickAnotherProvider(): void
    {
        $settings = $this->settings(['provider' => 'cloudflare']);

        $this->assertSame('google', $settings->describeFor(['verify_provider' => 'google'])['provider']);
        $this->assertSame('dns.google', $settings->describeFor(['verify_provider' => 'google'])['endpoint']);
    }

    public function testARuleCanPickAProviderWithNoGlobalDefault(): void
    {
        $this->assertSame('google', ReverseDnsSettings::current()->describeFor(['verify_provider' => 'google'])['provider']);
    }

    public function testTheSharedTimeoutReachesADnsOverHttpsResolver(): void
    {
        $settings = $this->settings(['provider' => 'cloudflare', 'timeout_ms' => 450]);

        $resolver = $settings->resolverFor([]);
        $this->assertInstanceOf(DnsOverHttpResolver::class, $resolver);
        $this->assertSame(450, $resolver->timeoutMs());

        $ruleResolver = $settings->resolverFor(['verify_timeout_ms' => 700]);
        $this->assertInstanceOf(DnsOverHttpResolver::class, $ruleResolver);
        $this->assertSame(700, $ruleResolver->timeoutMs());
    }

    public function testTheBreakerThresholdFollowsTheTimeout(): void
    {
        $settings = $this->settings(['provider' => 'cloudflare', 'timeout_ms' => 400]);

        $this->assertSame(850.0, $settings->slowThresholdFor([]));
        $this->assertSame(650.0, $this->settings(['provider' => 'cloudflare'])->slowThresholdFor([]));
        $this->assertSame(250.0, $this->settings(['provider' => 'cloudflare', 'timeout_ms' => 50])->slowThresholdFor([]));
    }

    public function testTheSameChoiceIsBuiltOnce(): void
    {
        $settings = $this->settings(['provider' => 'cloudflare']);

        $this->assertSame($settings->resolverFor([]), $settings->resolverFor(['verify_provider' => 'cloudflare']));
    }

    public function testASitesOwnProviderIsUsedWhole(): void
    {
        $settings = $this->settings([
            'provider' => 'internal',
            'timeout_ms' => 200,
            'providers' => [
                'internal' => ['resolver' => ScriptedResolver::class, 'options' => ['base_url' => 'https://dns.internal']],
            ],
        ]);

        $this->assertInstanceOf(ScriptedResolver::class, $settings->resolverFor([]));
        // The shared timeout is DnsOverHttpResolver's; a site's own class takes its own options.
        $this->assertSame([['base_url' => 'https://dns.internal']], ScriptedResolver::$built);
        $this->assertSame(250.0, $settings->slowThresholdFor([]));
        $this->assertSame(
            ['resolver' => ScriptedResolver::class, 'provider' => 'internal', 'endpoint' => null, 'address' => null],
            $settings->describeFor([])
        );
    }

    public function testAResolverCanBeNamedDirectly(): void
    {
        $settings = $this->settings([
            'resolver' => '\\' . ScriptedResolver::class,
            'resolver_options' => ['base_url' => 'https://dns.internal'],
        ]);

        $this->assertInstanceOf(ScriptedResolver::class, $settings->resolverFor([]));
        $this->assertSame([['base_url' => 'https://dns.internal']], ScriptedResolver::$built);
        $this->assertNull($settings->describeFor([])['provider']);
    }

    public function testDnsOverHttpsCanBeNamedDirectly(): void
    {
        $settings = $this->settings([
            'resolver' => DnsOverHttpResolver::class,
            'resolver_options' => ['endpoint' => self::INTERNAL_ENDPOINT],
        ]);

        $this->assertSame('resolver.internal', $settings->describeFor([])['endpoint']);
        $this->assertNull($settings->describeFor([])['address']);
    }

    public function testAnUnusableEndpointIsNotDescribed(): void
    {
        $settings = $this->settings([
            'resolver' => DnsOverHttpResolver::class,
            'resolver_options' => ['endpoint' => 'nope'],
        ]);

        $this->assertNull($settings->describeFor([])['endpoint']);
    }

    public function testAResolverWithNoConstructorIsBuilt(): void
    {
        $this->assertInstanceOf(NoOptionsResolver::class, $this->settings(['resolver' => NoOptionsResolver::class])->resolverFor([]));
    }

    public function testAnOptionalCollaboratorIsLeftToItsDefault(): void
    {
        $resolver = $this->settings(['resolver' => OptionalArgumentResolver::class, 'resolver_options' => ['a' => 1]])->resolverFor([]);

        $this->assertInstanceOf(OptionalArgumentResolver::class, $resolver);
        $this->assertSame(['a' => 1], $resolver->options);
        $this->assertNull($resolver->clock);
    }

    public function testAResolverThatCannotTakeOptionsIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('$clock is not an array of options');

        $this->settings(['resolver' => UnbuildableResolver::class])->resolverFor([]);
    }

    public function testAResolverThatThrowsWhileBuildingIsRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('cannot be built: no base_url');

        $this->settings(['resolver' => ThrowingConstructorResolver::class])->resolverFor([]);
    }

    public function testAnUndefinedProviderCannotBeUsed(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('provider "nowhere" is not defined');

        $this->settings(['provider' => 'nowhere'])->resolverFor([]);
    }

    public function testConfigureRefusesWhatCannotBeUsed(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('global.reverse_dns: "cloudfare" is not a provider; the providers are cloudflare, google');

        ReverseDnsSettings::configure(['reverse_dns' => ['provider' => 'cloudfare']]);
    }

    public function testConfigureMakesTheSettingsCurrent(): void
    {
        ReverseDnsSettings::configure(['reverse_dns' => ['provider' => 'google']]);

        $this->assertSame('google', ReverseDnsSettings::current()->describeFor([])['provider']);

        ReverseDnsSettings::reset();

        $this->assertNull(ReverseDnsSettings::current()->describeFor([])['provider']);
    }

    public function testEveryBuiltInProviderIsUsable(): void
    {
        foreach (BuiltinProviders::ALL as $name => $definition) {
            $this->assertSame([], DnsOverHttpResolver::problems($definition['options']), $name);
            $this->assertTrue(BuiltinProviders::has($name));
        }

        $this->assertSame(['cloudflare', 'google'], BuiltinProviders::names());
        $this->assertFalse(BuiltinProviders::has('quad9'));
    }

    public function testUsableSettingsHaveNoProblems(): void
    {
        $this->assertSame([], ReverseDnsSettings::problems([]));
        $this->assertSame([], ReverseDnsSettings::problems(['reverse_dns' => null]));
        $this->assertSame([], ReverseDnsSettings::problems(
            ['reverse_dns' => [
                'provider' => 'internal',
                'timeout_ms' => 300,
                'providers' => [
                    'internal' => ['resolver' => DnsOverHttpResolver::class, 'options' => ['endpoint' => self::INTERNAL_ENDPOINT, 'address' => '10.0.0.53']],
                    'platform' => ['resolver' => ScriptedResolver::class],
                ],
            ]],
            [
                ['plugin' => 'X', 'metadata' => ['verify_provider' => 'platform', 'verify_timeout_ms' => 500]],
                ['plugin' => 'Y'],
                'not a plugin entry',
            ]
        ));
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function unusableSettings(): array
    {
        return [
            'not a map' => ['cloudflare', 'must be a map, not string'],
            'an unknown key' => [['servers' => []], 'unknown key "servers"'],
            'providers that are not a map' => [['providers' => 'x'], 'providers must be a map'],
            'a provider that is not a name' => [['provider' => ''], 'provider must be a provider name'],
            'a provider nobody defined' => [['provider' => 'quad9'], '"quad9" is not a provider'],
            'provider and resolver' => [
                ['provider' => 'cloudflare', 'resolver' => ScriptedResolver::class],
                'provider and resolver are both set',
            ],
            'provider and resolver_options' => [
                ['provider' => 'cloudflare', 'resolver_options' => []],
                'resolver_options is set with provider',
            ],
            'resolver_options alone' => [['resolver_options' => ['a' => 1]], 'resolver_options is set without a resolver'],
            'a resolver that is not a name' => [['resolver' => 12], 'resolver must be a fully-qualified class name'],
            'a provider written as a resolver' => [['resolver' => 'cloudflare'], '"cloudflare" is a provider, not a resolver'],
            'a short name' => [['resolver' => 'doh'], 'class doh does not exist'],
            'a class that is not a resolver' => [['resolver' => \ArrayObject::class], 'does not implement'],
            'resolver options that are not a map' => [
                ['resolver' => ScriptedResolver::class, 'resolver_options' => 'x'],
                'resolver options must be a map',
            ],
            'unusable DNS-over-HTTPS options' => [
                ['resolver' => DnsOverHttpResolver::class, 'resolver_options' => ['endpoint' => 'http://x/']],
                'resolver options: endpoint: the template must be an https:// URL',
            ],
            'a timeout that is not one' => [['timeout_ms' => '300'], 'timeout_ms must be a whole number'],
            'a built-in name redefined' => [
                ['providers' => ['cloudflare' => ['resolver' => DnsOverHttpResolver::class]]],
                'built-in names are reserved; define yours under another name, such as "cloudflare-custom"',
            ],
            'a provider name with capitals' => [['providers' => ['Internal' => []]], 'a provider name is lower-case'],
            'a provider that is not a map' => [['providers' => ['internal' => 'x']], 'providers.internal must be a map'],
            'a provider with an unknown key' => [
                ['providers' => ['internal' => ['resolver' => ScriptedResolver::class, 'endpoint' => 'x']]],
                'providers.internal: unknown key "endpoint"',
            ],
            'a provider with no resolver' => [['providers' => ['internal' => ['options' => []]]], 'providers.internal: resolver is required'],
            'a provider whose resolver is missing' => [
                ['providers' => ['internal' => ['resolver' => 'App\\Missing']]],
                'providers.internal.resolver: class App\\Missing does not exist',
            ],
        ];
    }

    #[DataProvider('unusableSettings')]
    public function testUnusableSettingsAreNamed(mixed $reverseDns, string $expected): void
    {
        $this->assertStringContainsString($expected, implode('; ', ReverseDnsSettings::problems(['reverse_dns' => $reverseDns])));
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function unusableRules(): array
    {
        return [
            'a provider that is not a name' => [['name' => 'crawlers', 'verify_provider' => 5], 'rule "crawlers" verify_provider must be a provider name'],
            'a provider nobody defined' => [['verify_provider' => 'nextdns'], 'rule "#0" verify_provider: "nextdns" is not a provider'],
            'a timeout that is not one' => [['verify_timeout_ms' => 0], 'rule "#0" verify_timeout_ms must be'],
            'a resolver of its own' => [['verify_resolver' => ScriptedResolver::class], 'sets verify_resolver; a rule picks a provider with verify_provider'],
            'resolver options of its own' => [['verify_resolver_options' => []], 'sets verify_resolver_options'],
        ];
    }

    /**
     * @param array<string, mixed> $metadata
     */
    #[DataProvider('unusableRules')]
    public function testUnusableRulesAreNamed(array $metadata, string $expected): void
    {
        $this->assertStringContainsString(
            $expected,
            implode('; ', ReverseDnsSettings::problems([], [['plugin' => 'X', 'metadata' => $metadata]]))
        );
    }
}
