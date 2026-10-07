<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Utility\ReverseDns\DnsOverHttpResolver;
use Kanopi\Firewall\Utility\ReverseDns\LookupResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Lookups over DNS over HTTPS (#473).
 *
 * The request itself is a seam, so nothing here touches the network: each test scripts what
 * the provider answers and checks what was asked.
 */
class DnsOverHttpResolverTest extends TestCase
{
    private const ENDPOINT = 'https://cloudflare-dns.com/dns-query?name={{ dns.name }}&type={{ dns.type }}';

    /**
     * A resolver whose requests answer from a script.
     *
     * @param array<string, mixed> $options
     * @param array<string, array{status: int, body: string}|string> $answers
     *   By URL.
     */
    private function resolver(array $options, array $answers = []): DnsOverHttpResolver
    {
        return new class ($options, $answers) extends DnsOverHttpResolver {
            /**
             * @var list<string>
             */
            public array $requested = [];

            /**
             * @param array<string, mixed> $options
             * @param array<string, array{status: int, body: string}|string> $answers
             */
            public function __construct(array $options, private readonly array $answers)
            {
                parent::__construct($options);
            }

            protected function fetch(string $url): array|string
            {
                $this->requested[] = $url;

                return $this->answers[$url] ?? 'request failed: no script for ' . $url;
            }

            /**
             * @return list<string>
             */
            public function pins(): array
            {
                return $this->resolveEntries();
            }
        };
    }

    public function testAReverseLookupAsksForThePtrRecord(): void
    {
        $url = 'https://cloudflare-dns.com/dns-query?name=1.66.249.66.in-addr.arpa&type=PTR';
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT], [
            $url => ['status' => 200, 'body' => '{"Status":0,"Answer":[{"type":12,"data":"crawl-66-249-66-1.googlebot.com."}]}'],
        ]);

        $this->assertSame(['crawl-66-249-66-1.googlebot.com.'], $resolver->reverse('66.249.66.1')->values);
        $this->assertSame([$url], $resolver->requested);
    }

    public function testAForwardLookupAsksForTheClientsFamily(): void
    {
        $url = 'https://cloudflare-dns.com/dns-query?name=crawl.googlebot.com&type=AAAA';
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT], [
            $url => ['status' => 200, 'body' => '{"Status":0,"Answer":[{"type":28,"data":"2001:4860:4801::1"}]}'],
        ]);

        $this->assertSame(['2001:4860:4801::1'], $resolver->forward('crawl.googlebot.com', 'AAAA')->values);
    }

    public function testAFailedRequestIsUnknown(): void
    {
        $lookupResult = $this->resolver(['endpoint' => self::ENDPOINT])->reverse('192.0.2.1');

        $this->assertTrue($lookupResult->isUnknown());
        $this->assertStringContainsString('request failed', $lookupResult->reason);
    }

    public function testAnErrorStatusIsUnknown(): void
    {
        $url = 'https://cloudflare-dns.com/dns-query?name=1.2.0.192.in-addr.arpa&type=PTR';
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT], [$url => ['status' => 502, 'body' => '']]);

        $this->assertSame(LookupResult::UNKNOWN, $resolver->reverse('192.0.2.1')->status);
    }

    public function testItSaysWhereItSendsAndHowLongItWaits(): void
    {
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT, 'address' => '1.1.1.1', 'timeout_ms' => 150]);

        $this->assertSame('cloudflare-dns.com', $resolver->host());
        $this->assertSame('1.1.1.1', $resolver->address());
        $this->assertSame(150, $resolver->timeoutMs());
        $this->assertSame(['cloudflare-dns.com:443:1.1.1.1'], $resolver->pins());
    }

    public function testAnIpv6AddressIsPinnedInBrackets(): void
    {
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT, 'address' => '2606:4700:4700::1111']);

        $this->assertSame(['cloudflare-dns.com:443:[2606:4700:4700::1111]'], $resolver->pins());
    }

    public function testWithoutAnAddressNothingIsPinned(): void
    {
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT]);

        $this->assertSame([], $resolver->pins());
        $this->assertNull($resolver->address());
        $this->assertSame(DnsOverHttpResolver::DEFAULT_TIMEOUT_MS, $resolver->timeoutMs());
    }

    public function testCustomHeadersAreAccepted(): void
    {
        $resolver = $this->resolver(['endpoint' => self::ENDPOINT, 'headers' => ['Accept' => 'application/json', 'X-Token' => 'abc']]);

        $this->assertSame('cloudflare-dns.com', $resolver->host());
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function unusableOptions(): array
    {
        return [
            'no endpoint' => [[], 'endpoint is required'],
            'an unusable endpoint' => [['endpoint' => 'http://x.example/'], 'endpoint: the template must be an https:// URL'],
            'an unknown option' => [['endpoint' => self::ENDPOINT, 'retries' => 2], 'unknown option "retries"'],
            'an address that is not one' => [['endpoint' => self::ENDPOINT, 'address' => 'one.one.one.one'], 'address must be an IP address'],
            'headers that are not a map' => [['endpoint' => self::ENDPOINT, 'headers' => 'Accept: x'], 'headers must be a map'],
            'a header with a line break' => [['endpoint' => self::ENDPOINT, 'headers' => ['X-A' => "a\r\nX-B: b"]], '"X-A" is not a usable header'],
            'a header name with a space' => [['endpoint' => self::ENDPOINT, 'headers' => ['X A' => 'a']], '"X A" is not a usable header'],
            'a header with a numeric name' => [['endpoint' => self::ENDPOINT, 'headers' => ['a']], '"0" is not a usable header'],
            'a timeout of zero' => [['endpoint' => self::ENDPOINT, 'timeout_ms' => 0], 'timeout_ms must be'],
            'a timeout that is too long' => [['endpoint' => self::ENDPOINT, 'timeout_ms' => 60000], 'timeout_ms must be'],
            'a timeout that is text' => [['endpoint' => self::ENDPOINT, 'timeout_ms' => '300'], 'timeout_ms must be'],
            'an unusable response' => [['endpoint' => self::ENDPOINT, 'response' => 'dns-xml'], 'response: "dns-xml" is not a known layout'],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[DataProvider('unusableOptions')]
    public function testUnusableOptionsAreNamed(array $options, string $expected): void
    {
        $this->assertStringContainsString($expected, implode('; ', DnsOverHttpResolver::problems($options)));
    }

    public function testWithoutCurlItCannotBeUsed(): void
    {
        $withoutCurl = new class extends DnsOverHttpResolver {
            // Built without the parent's constructor, which would refuse it for the very
            // reason this test checks.
            public function __construct()
            {
            }

            protected static function curlAvailable(): bool
            {
                return false;
            }
        };

        $this->assertContains('DnsOverHttpResolver needs the curl extension, which is not loaded', $withoutCurl::problems(['endpoint' => self::ENDPOINT]));
    }

    public function testUnusableOptionsAreRefused(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('endpoint is required');

        new DnsOverHttpResolver([]);
    }
}
