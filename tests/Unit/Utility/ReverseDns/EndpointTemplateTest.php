<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\ReverseDns\EndpointTemplate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The URL a DNS-over-HTTPS provider is asked (#473).
 */
class EndpointTemplateTest extends TestCase
{
    private const CLOUDFLARE = 'https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}';

    public function testOneTemplateMakesBothLookups(): void
    {
        $endpointTemplate = EndpointTemplate::fromConfig(self::CLOUDFLARE);

        $this->assertSame(
            'https://cloudflare-dns.com/dns-query?name=1.66.249.66.in-addr.arpa&type=PTR',
            $endpointTemplate->ptrUrl('66.249.66.1')
        );
        $this->assertSame(
            'https://cloudflare-dns.com/dns-query?name=crawl-66-249-66-1.googlebot.com&type=A',
            $endpointTemplate->forwardUrl('crawl-66-249-66-1.googlebot.com', 'A', '66.249.66.1')
        );
    }

    public function testPlaceholdersMayBeWrittenWithoutSpaces(): void
    {
        $endpointTemplate = EndpointTemplate::fromConfig('https://dns.example/q?n={{dns.name}}&t={{dns.type}}');

        $this->assertSame('https://dns.example/q?n=1.0.2.192.in-addr.arpa&t=PTR', $endpointTemplate->ptrUrl('192.2.0.1'));
    }

    public function testValuesAreUrlEncoded(): void
    {
        $endpointTemplate = EndpointTemplate::fromConfig(self::CLOUDFLARE);

        $this->assertStringContainsString(
            'name=a%26b%3Fc&type=A',
            $endpointTemplate->forwardUrl('a&b?c', 'A', '192.0.2.1')
        );
    }

    public function testAMapGivesEachLookupItsOwnUrl(): void
    {
        $endpointTemplate = EndpointTemplate::fromConfig([
            'ptr' => 'https://resolver.internal/ptr/{{ client.ip }}?arpa={{ client.ip_arpa }}',
            'forward' => 'https://resolver.internal/lookup?name={{ dns.name }}&type={{ dns.type }}&for={{ client.ip }}',
        ]);

        $this->assertSame(
            'https://resolver.internal/ptr/192.0.2.1?arpa=1.2.0.192.in-addr.arpa',
            $endpointTemplate->ptrUrl('192.0.2.1')
        );
        $this->assertSame(
            'https://resolver.internal/lookup?name=crawl.example&type=AAAA&for=2001%3Adb8%3A%3A1',
            $endpointTemplate->forwardUrl('crawl.example', 'AAAA', '2001:db8::1')
        );
    }

    public function testTheHostAndPortAreTheTemplates(): void
    {
        $this->assertSame('cloudflare-dns.com', EndpointTemplate::fromConfig(self::CLOUDFLARE)->host());
        $this->assertSame(443, EndpointTemplate::fromConfig(self::CLOUDFLARE)->port());
        $this->assertSame(8443, EndpointTemplate::fromConfig('https://dns.example:8443/q?n={{ dns.name }}&t={{ dns.type }}')->port());
    }

    public function testTheReverseNameOfAnIpv4Address(): void
    {
        $this->assertSame('1.66.249.66.in-addr.arpa', EndpointTemplate::arpa('66.249.66.1'));
    }

    public function testTheReverseNameOfAnIpv6Address(): void
    {
        $this->assertSame(
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
            EndpointTemplate::arpa('2001:db8::1')
        );
    }

    public function testSomethingThatIsNotAnAddressHasNoReverseName(): void
    {
        $this->assertSame('', EndpointTemplate::arpa('not-an-ip'));
    }

    public function testAnUnusableTemplateIsRefusedWithEveryProblem(): void
    {
        try {
            EndpointTemplate::fromConfig('http://dns.example/q?name={{ dns.nme }}');
            $this->fail('An unusable template was accepted');
        } catch (ConfigurationException $configurationException) {
            $this->assertStringContainsString('{{ dns.nme }}, which is not a placeholder', $configurationException->getMessage());
            $this->assertStringContainsString('must be an https:// URL', $configurationException->getMessage());
            $this->assertStringContainsString('must contain {{ dns.name }}', $configurationException->getMessage());
            $this->assertStringContainsString('must contain {{ dns.type }}', $configurationException->getMessage());
        }
    }

    /**
     * @return array<string, array{0: mixed, 1: string}>
     */
    public static function unusableTemplates(): array
    {
        return [
            'a fixed record type' => ['https://dns.example/q?name={{ dns.name }}&type=PTR', 'must contain {{ dns.type }}'],
            'no host' => ['https:///q?name={{ dns.name }}&type={{ dns.type }}', 'has no host'],
            'a placeholder in the host' => ['https://{{ dns.name }}.example/q?t={{ dns.type }}', 'puts a placeholder in the host'],
            'neither text nor a map' => [42, 'got int'],
            'a map with an unknown key' => [
                ['ptr' => 'https://d.example/{{ dns.name }}', 'forward' => 'https://d.example/{{ dns.name }}', 'extra' => 'x'],
                'unknown key "extra"',
            ],
            'a map missing forward' => [['ptr' => 'https://d.example/{{ dns.name }}'], 'forward must be a URL template'],
            'a map whose ptr cannot name the address' => [
                ['ptr' => 'https://d.example/ptr', 'forward' => 'https://d.example/{{ dns.name }}'],
                'ptr must contain',
            ],
            'a map whose forward cannot name the host' => [
                ['ptr' => 'https://d.example/{{ client.ip }}', 'forward' => 'https://d.example/{{ client.ip }}'],
                'forward must contain {{ dns.name }}',
            ],
            'a map on two hosts' => [
                ['ptr' => 'https://a.example/{{ dns.name }}', 'forward' => 'https://b.example/{{ dns.name }}'],
                'the same host and port',
            ],
            'a map on two ports' => [
                ['ptr' => 'https://a.example/{{ dns.name }}', 'forward' => 'https://a.example:8443/{{ dns.name }}'],
                'the same host and port',
            ],
            'a map with a plain-HTTP step' => [
                ['ptr' => 'http://a.example/{{ dns.name }}', 'forward' => 'https://a.example/{{ dns.name }}'],
                'ptr must be an https:// URL',
            ],
        ];
    }

    #[DataProvider('unusableTemplates')]
    public function testUnusableTemplatesAreNamed(mixed $template, string $expected): void
    {
        $this->assertStringContainsString($expected, implode('; ', EndpointTemplate::problems($template)));
    }

    public function testAUsableMapHasNoProblems(): void
    {
        $this->assertSame([], EndpointTemplate::problems([
            'ptr' => 'https://a.example/ptr/{{ client.ip_arpa }}',
            'forward' => 'https://A.example/fwd?n={{ dns.name }}&t={{ dns.type }}',
        ]));
    }
}
