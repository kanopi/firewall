<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\GeoLocation;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests reading geolocation from the headers a CDN adds at the edge.
 *
 * The trust gate carries most of the weight here. A geo header is a claim, and
 * believing an unverified one against a `response: allow` entry is not a
 * weakened control but a complete bypass — an allow match short-circuits
 * everything after it.
 */
class GeoHeaderSourceTest extends AbstractTestCase
{
    /**
     * Captures what the plugin logs.
     */
    private TestHandler $handler;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new TestHandler(Level::Debug);
        $logger = new Logger('geo-header');
        $logger->pushHandler($this->handler);
        LoggingFactory::setLogger($logger);

        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        // Trusted proxies are process-global; leaving them set would change
        // how every later test resolves a client address.
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
        parent::tearDown();
    }

    /**
     * Treat requests from the test address as arriving via the edge.
     */
    private function trustTheEdge(): void
    {
        Request::setTrustedProxies(['203.0.113.0/24'], Request::HEADER_X_FORWARDED_FOR);
    }

    /**
     * A request carrying edge headers.
     *
     * @param array<string, string> $headers
     *   Header name to value.
     */
    private function request(array $headers): Request
    {
        $server = ['REMOTE_ADDR' => '203.0.113.9'];

        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return Request::create('/', 'GET', [], [], [], $server);
    }

    /**
     * A header-sourced plugin.
     *
     * @param array<array-key, mixed> $metadata
     *   Extra metadata merged over the header source.
     * @param array<int, mixed> $config
     *   Rules.
     */
    private function plugin(array $metadata, array $config): GeoLocation
    {
        return new GeoLocation(['source' => 'header'] + $metadata, $config);
    }

    /**
     * An untrusted request cannot pick its own country.
     *
     * This is the test the feature exists around. Without it, `curl -H
     * "CF-IPCountry: US"` straight at the origin defeats geo blocking.
     */
    public function testHeadersAreIgnoredWhenTheRequestIsNotFromATrustedProxy(): void
    {
        $plugin = $this->plugin(['provider' => 'cloudflare'], ['country:CN']);

        $this->assertFalse($plugin->evaluate($this->request(['CF-IPCountry' => 'CN'])));
    }

    /**
     * ...and says so, rather than quietly matching nothing.
     *
     * A geo plugin that silently never fires looks exactly like "nobody from
     * those countries is visiting".
     */
    public function testIgnoringHeadersIsReportedLoudly(): void
    {
        $this->plugin(['provider' => 'cloudflare'], ['country:CN'])
            ->evaluate($this->request(['CF-IPCountry' => 'CN']));

        $this->assertTrue(
            $this->handler->hasRecordThatContains('did not arrive via a trusted proxy', Level::Warning)
        );
    }

    /**
     * With the edge trusted, the header decides.
     */
    public function testTrustedEdgeHeadersAreBelieved(): void
    {
        $this->trustTheEdge();
        $plugin = $this->plugin(['provider' => 'cloudflare'], ['country:CN']);

        $this->assertTrue($plugin->evaluate($this->request(['CF-IPCountry' => 'CN'])));
        $this->assertFalse($plugin->evaluate($this->request(['CF-IPCountry' => 'US'])));
    }

    /**
     * A request with no geo header at all matches nothing.
     */
    public function testMissingHeadersMatchNothing(): void
    {
        $this->trustTheEdge();

        $this->assertFalse($this->plugin(['provider' => 'cloudflare'], ['country:CN'])->evaluate($this->request([])));
    }

    /**
     * Each known provider reads its own header layout.
     *
     * @param string $provider
     *   The provider name.
     * @param array<string, string> $headers
     *   Headers that provider would send.
     */
    #[DataProvider('providerHeadersProvider')]
    public function testEachProviderReadsItsOwnHeaders(string $provider, array $headers): void
    {
        $this->trustTheEdge();

        $this->assertTrue(
            $this->plugin(['provider' => $provider], ['country@in:CN,RU'])->evaluate($this->request($headers)),
            $provider
        );
    }

    /**
     * The header each CDN uses for country.
     */
    public static function providerHeadersProvider(): array
    {
        return [
            'cloudflare' => ['cloudflare', ['CF-IPCountry' => 'CN']],
            'cloudfront' => ['cloudfront', ['CloudFront-Viewer-Country' => 'RU']],
            'akamai' => ['akamai', ['X-Akamai-Edgescape' => 'georegion=263,country_code=CN,city=BEIJING']],
        ];
    }

    /**
     * Akamai packs everything into one header, and every field is readable.
     */
    public function testAkamaiCompoundHeaderIsUnpacked(): void
    {
        $this->trustTheEdge();

        $edgescape = 'georegion=263,country_code=US,region_code=CA,city=SANJOSE,lat=37.3,long=-121.9,zip=95101';

        foreach (
            [
                'country:US',
                'region:CA',
                'city:SANJOSE',
                'postal:95101',
                'location.latitude:37.3',
                'location.longitude:-121.9',
            ] as $rule
        ) {
            $this->assertTrue(
                $this->plugin(['provider' => 'akamai'], [$rule])->evaluate($this->request(['X-Akamai-Edgescape' => $edgescape])),
                $rule
            );
        }
    }

    /**
     * An unrecognised Edgescape key costs nothing else.
     */
    public function testUnknownAkamaiKeysAreIgnored(): void
    {
        $this->trustTheEdge();

        $this->assertTrue(
            $this->plugin(['provider' => 'akamai'], ['country:US'])
                ->evaluate($this->request(['X-Akamai-Edgescape' => 'something_new=1,country_code=US'])),
            'Akamai adds fields over time; a new one must not cost the fields we understood.'
        );
    }

    /**
     * A custom mapping covers an edge that adds no geo header of its own.
     *
     * Fastly is the case: it emits nothing until VCL sets something.
     */
    public function testCustomProviderReadsAnOperatorNamedHeader(): void
    {
        $this->trustTheEdge();

        $plugin = $this->plugin(
            ['provider' => 'custom', 'headers' => ['country' => 'X-Geo-Country', 'city' => 'X-Geo-City']],
            ['country:DE']
        );

        $this->assertTrue($plugin->evaluate($this->request(['X-Geo-Country' => 'DE'])));
        $this->assertFalse($plugin->evaluate($this->request(['X-Geo-Country' => 'FR'])));
    }

    /**
     * An explicit header overrides a provider's default for that field only.
     */
    public function testExplicitHeadersOverrideProviderDefaults(): void
    {
        $this->trustTheEdge();

        $plugin = $this->plugin(
            ['provider' => 'cloudflare', 'headers' => ['country' => 'X-Real-Country']],
            ['country:JP']
        );

        $this->assertTrue($plugin->evaluate($this->request(['X-Real-Country' => 'JP', 'CF-IPCountry' => 'US'])));
    }

    /**
     * Rules written for the reader keep working against headers.
     *
     * `country` and `country.isoCode` are the same question, and a config that
     * moves from a MaxMind reader to edge headers should not have to be
     * rewritten.
     */
    public function testReaderVocabularyStillResolves(): void
    {
        $this->trustTheEdge();

        foreach (['country:CN', 'country.isoCode:CN'] as $rule) {
            $this->assertTrue(
                $this->plugin(['provider' => 'cloudflare'], [$rule])->evaluate($this->request(['CF-IPCountry' => 'CN'])),
                $rule
            );
        }
    }

    /**
     * A field the edge did not send resolves to nothing, not to a wrong answer.
     *
     * Cloudflare sends no country name, so a rule asking for one must not match
     * on the ISO code that happens to be there.
     */
    public function testFieldsTheEdgeDidNotSendDoNotMatch(): void
    {
        $this->trustTheEdge();

        $this->assertFalse(
            $this->plugin(['provider' => 'cloudflare'], ['country.name:China'])
                ->evaluate($this->request(['CF-IPCountry' => 'CN']))
        );
    }

    /**
     * Misconfiguration is refused at construction rather than at request time.
     *
     * @param array<array-key, mixed> $metadata
     *   A broken header-source configuration.
     * @param string $expected
     *   Text the error should carry.
     */
    #[DataProvider('badConfigProvider')]
    public function testBadConfigurationIsRefused(array $metadata, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($expected);

        $this->plugin($metadata, ['country:CN']);
    }

    /**
     * Header-source configurations that cannot work.
     */
    public static function badConfigProvider(): array
    {
        return [
            'unknown provider' => [['provider' => 'akamai-lite'], 'metadata.provider must be one of'],
            'custom with no headers' => [['provider' => 'custom'], 'needs metadata.headers'],
            'unknown field' => [
                ['provider' => 'custom', 'headers' => ['planet' => 'X-Planet']],
                'unknown geo field',
            ],
            'headers not a map' => [
                ['provider' => 'custom', 'headers' => 'X-Geo-Country'],
                'metadata.headers must be a map',
            ],
        ];
    }

    /**
     * The reader remains the default, so no existing config changes.
     */
    public function testReaderIsStillTheDefaultSource(): void
    {
        $plugin = new GeoLocation([], ['country:CN']);

        $this->assertFalse(
            $plugin->evaluate($this->request(['CF-IPCountry' => 'CN'])),
            'Without source: header, edge headers must be ignored entirely.'
        );
    }

    /**
     * An unknown source falls back to the reader and warns.
     */
    public function testUnknownSourceFallsBackToTheReader(): void
    {
        $plugin = new GeoLocation(['source' => 'psychic'], ['country:CN']);

        $this->assertFalse($plugin->evaluate($this->request(['CF-IPCountry' => 'CN'])));
        $this->assertTrue($this->handler->hasRecordThatContains('Unknown GeoLocation source', Level::Warning));
    }
}
