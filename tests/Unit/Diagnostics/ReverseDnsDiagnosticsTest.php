<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Diagnostics;

use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Diagnostics\Doctor;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ScriptedResolver;
use Kanopi\Firewall\Tests\Unit\Utility\ReverseDns\Fixtures\ThrowingConstructorResolver;
use Kanopi\Firewall\Utility\DegradedBackends;
use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;

/**
 * `global.reverse_dns` is checked before the first request, and reported on (#473).
 */
class ReverseDnsDiagnosticsTest extends AbstractTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir() . '/fw-rdns-' . uniqid();
        mkdir($this->dir, 0700, true);
        DegradedBackends::reset();
        ReverseDnsSettings::reset();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);
        DegradedBackends::reset();
        ReverseDnsSettings::reset();
        parent::tearDown();
    }

    /**
     * A working configuration with one verified crawler rule.
     *
     * @param array<string, mixed> $reverseDns
     * @param array<string, mixed> $metadata
     *
     * @return array<string, mixed>
     */
    private function config(array $reverseDns = [], array $metadata = []): array
    {
        return [
            'global' => ['mode' => 'block'] + ($reverseDns === [] ? [] : ['reverse_dns' => $reverseDns]),
            'storage' => [
                'type' => 'Kanopi\\Firewall\\Storage\\FileStorage',
                'config' => ['storage_file' => $this->dir . '/blocked.data'],
            ],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\UserAgent',
                    'response' => 'allow',
                    'metadata' => $metadata + [
                        'name' => 'crawlers',
                        'verify' => 'reverse-dns',
                        'verify_suffixes' => ['.googlebot.com'],
                    ],
                    'config' => ['bot:true'],
                ],
                [
                    'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                    'response' => 'block',
                    'config' => ['203.0.113.5'],
                ],
            ],
        ];
    }

    /**
     * @param array<int, Diagnosis> $findings
     *
     * @return array<int, string>
     */
    private function titles(array $findings, string $status): array
    {
        return array_values(array_map(
            static fn(Diagnosis $diagnosis): string => $diagnosis->title,
            array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status === $status)
        ));
    }

    /**
     * @param array<int, Diagnosis> $findings
     */
    private function finding(array $findings, string $title): Diagnosis
    {
        foreach ($findings as $finding) {
            if ($finding->title === $title) {
                return $finding;
            }
        }

        $this->fail(sprintf('No finding titled "%s"', $title));
    }

    public function testTheFirewallRefusesToStartWithAProviderThatDoesNotExist(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('global.reverse_dns: "cloudfare" is not a provider');

        Firewall::create([$this->config(['provider' => 'cloudfare'])]);
    }

    public function testTheFirewallRefusesARuleNamingAProviderThatDoesNotExist(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('rule "crawlers" verify_provider: "quad9" is not a provider');

        Firewall::create([$this->config([], ['verify_provider' => 'quad9'])]);
    }

    public function testTheFirewallRefusesAResolverThatCannotBeBuilt(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('cannot be built: no base_url');

        Firewall::create([$this->config(
            ['providers' => ['platform' => ['resolver' => ThrowingConstructorResolver::class]]],
            ['verify_provider' => 'platform']
        )]);
    }

    public function testStartingMakesTheSettingsTheOnesRulesRead(): void
    {
        Firewall::create([$this->config(['provider' => 'google'])]);

        $this->assertSame('google', ReverseDnsSettings::current()->describeFor([])['provider']);
    }

    public function testTheLinterReportsWhatTheFirewallWouldRefuse(): void
    {
        $findings = (new ConfigLinter([$this->config(['provider' => 'cloudflare', 'resolver' => ScriptedResolver::class])]))->run();

        $errors = $this->titles($findings, Diagnosis::ERROR);
        $this->assertContains('global.reverse_dns cannot be used: provider and resolver are both set; set one. A provider brings its own resolver', $errors);
    }

    public function testTheLinterIsQuietAboutUsableSettings(): void
    {
        $findings = (new ConfigLinter([$this->config(['provider' => 'cloudflare'])]))->run();

        $this->assertSame([], array_filter(
            $this->titles($findings, Diagnosis::ERROR),
            static fn(string $title): bool => str_contains($title, 'reverse_dns')
        ));
    }

    public function testTheDoctorReportsWhatTheFirewallWouldRefuse(): void
    {
        $findings = (new Doctor([$this->config(['provider' => 'cloudfare'])]))->run();

        $this->assertContains(
            'global.reverse_dns cannot be used: "cloudfare" is not a provider; the providers are cloudflare, google',
            $this->titles($findings, Diagnosis::ERROR)
        );
    }

    public function testTheDoctorSaysARuleUsesPhpsOwnLookups(): void
    {
        $findings = (new Doctor([$this->config()]))->run();

        $this->assertContains('Rule crawlers verifies with PHP\'s own lookups', $this->titles($findings, Diagnosis::OK));
    }

    public function testTheDoctorSaysWhereAProviderSendsLookups(): void
    {
        $findings = (new Doctor([$this->config(['provider' => 'cloudflare'])]))->run();

        $finding = $this->finding($findings, 'Rule crawlers verifies through provider cloudflare');
        $this->assertSame(Diagnosis::OK, $finding->status);
        $this->assertStringContainsString('sent to cloudflare-dns.com, connecting to 1.1.1.1', $finding->detail);
    }

    public function testTheDoctorWarnsWhenAProvidersHostIsResolvedWithoutATimeLimit(): void
    {
        $findings = (new Doctor([$this->config([
            'resolver' => DnsOverHttpResolver::class,
            'resolver_options' => ['endpoint' => 'https://resolver.internal/q?name={{ dns.name }}&type={{ dns.type }}'],
        ])]))->run();

        $this->assertContains(
            'Rule crawlers verifies through resolver ' . DnsOverHttpResolver::class . ', whose host is looked up without a time limit',
            $this->titles($findings, Diagnosis::WARNING)
        );
    }

    public function testTheDoctorDoesNotWarnAboutAnEndpointThatIsAnAddress(): void
    {
        $findings = (new Doctor([$this->config([
            'resolver' => DnsOverHttpResolver::class,
            'resolver_options' => ['endpoint' => 'https://10.0.0.53/q?name={{ dns.name }}&type={{ dns.type }}'],
        ])]))->run();

        $finding = $this->finding($findings, 'Rule crawlers verifies through resolver ' . DnsOverHttpResolver::class);
        $this->assertSame('Visitors\' reverse-DNS names are sent to 10.0.0.53.', $finding->detail);
    }

    public function testTheDoctorNamesASitesOwnResolver(): void
    {
        $findings = (new Doctor([$this->config([
            'provider' => 'platform',
            'providers' => ['platform' => ['resolver' => ScriptedResolver::class]],
        ])]))->run();

        $finding = $this->finding($findings, 'Rule crawlers verifies through provider platform');
        $this->assertSame(ScriptedResolver::class, $finding->detail);
    }
}
