<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\EdgeSignal;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\Logger;
use Symfony\Component\HttpFoundation\Request;

/**
 * Matching on what the CDN decided (#206).
 *
 * The signals themselves are not computed here and are not tested here --
 * there is nothing to test about reading a header. What these cover is the two
 * things that make the rule either useful or dangerous: the trust boundary,
 * and the direction of the scale.
 */
final class EdgeSignalTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
    }

    protected function tearDown(): void
    {
        // Process-global. Leaving them set would change how every later test
        // in the run resolves a client address.
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        parent::tearDown();
    }

    /**
     * A signal that crosses the threshold matches.
     */
    public function testALowBotScoreMatches(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']);

        $this->assertTrue($rule->evaluate($this->request(['Cf-Bot-Score' => '2'])));
    }

    /**
     * And a high one does not, because high means human.
     */
    public function testAHighBotScoreDoesNotMatch(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']);

        $this->assertFalse($rule->evaluate($this->request(['Cf-Bot-Score' => '91'])));
    }

    /**
     * A fingerprint is matched as the string it is.
     */
    public function testATlsFingerprintMatches(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['ja3:e7d705a3286e19ea42f587b344ee6865']);

        $this->assertTrue($rule->evaluate($this->request(['Cf-Ja3-Hash' => 'e7d705a3286e19ea42f587b344ee6865'])));
        $this->assertFalse($rule->evaluate($this->request(['Cf-Ja3-Hash' => 'something-else'])));
    }

    /**
     * Nothing is believed from a request that did not come through the edge.
     *
     * The test that matters. Anyone can send `cf-bot-score: 1` -- or, against a
     * `response: allow` rule, `cf-bot-score: 99` -- straight to the origin, and
     * an allow match short-circuits everything after it. Without the gate this
     * rule is a bypass with a configuration file.
     */
    public function testAHeaderFromAnUntrustedSourceIsIgnored(): void
    {
        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']);

        $this->assertFalse(
            $rule->evaluate($this->request(['Cf-Bot-Score' => '1'])),
            'Without trusted proxies the header is a claim from the client and must not be read.'
        );
    }

    /**
     * And being ignored is said out loud.
     *
     * A rule matching nothing looks exactly like a quiet day. Nothing else in
     * the system would report that bot blocking is switched off.
     */
    public function testAnUntrustedRequestIsReported(): void
    {
        $handler = $this->captureLogs();

        (new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']))
            ->evaluate($this->request(['Cf-Bot-Score' => '1']));

        $this->assertTrue($handler->hasWarningContaining('did not arrive via a trusted proxy'));
    }

    /**
     * A signal the edge did not send is absent, not zero.
     *
     * The Managed Transform case: the request came through Cloudflare, the
     * header was never enabled. Reading a missing `bot_score` as `0` would make
     * every "block the obvious bots" rule match every visitor -- an outage
     * caused by a setting nobody turned on.
     */
    public function testAMissingSignalDoesNotMatchAsZero(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']);

        $this->assertFalse($rule->evaluate($this->request([])));
    }

    /**
     * A header that arrived empty is absent, not zero.
     *
     * An edge that sends `Cf-Bot-Score:` with nothing after it -- a transform
     * misconfigured rather than switched off -- must not read as a score of 0,
     * which is Cloudflare's "certainly a bot" end and would match every
     * bot-blocking rule ever written.
     */
    public function testAnEmptySignalIsTreatedAsAbsent(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']);

        $this->assertFalse($rule->evaluate($this->request(['Cf-Bot-Score' => '   '])));
    }

    /**
     * An edge that sent nothing at all says so at debug.
     */
    public function testAnEdgeThatSentNothingIsReported(): void
    {
        $this->trustTheEdge();
        $handler = $this->captureLogs();

        (new EdgeSignal(['provider' => 'cloudflare'], ['bot_score <= 5']))->evaluate($this->request([]));

        $messages = array_map(static fn(\Monolog\LogRecord $r): string => $r->message, $handler->records);

        $this->assertNotEmpty(
            array_filter($messages, static fn(string $m): bool => str_contains($m, 'edge headers carried nothing'))
        );
    }

    /**
     * Fastly's profile reads the names the documented VCL snippet sets.
     */
    public function testTheFastlyProfileReadsItsOwnNames(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(['provider' => 'fastly'], ['bot_score <= 5']);

        $this->assertTrue($rule->evaluate($this->request(['X-Edge-Bot-Score' => '3'])));
        $this->assertFalse($rule->evaluate($this->request(['Cf-Bot-Score' => '3'])));
    }

    /**
     * A custom mapping reads whatever the property was configured to send.
     *
     * The answer for Akamai and CloudFront, which have no fixed header names to
     * ship a profile for.
     */
    public function testACustomMappingReadsItsOwnHeaders(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(
            ['provider' => 'custom', 'headers' => ['bot_score' => 'Akamai-Bot-Score']],
            ['bot_score <= 5']
        );

        $this->assertTrue($rule->evaluate($this->request(['Akamai-Bot-Score' => '4'])));
    }

    /**
     * A custom name layers over a profile rather than replacing it.
     *
     * A zone that renamed one header should not have to restate the other
     * three.
     */
    public function testACustomNameLayersOverAProfile(): void
    {
        $this->trustTheEdge();

        $rule = new EdgeSignal(
            ['provider' => 'cloudflare', 'headers' => ['bot_score' => 'X-Renamed-Score']],
            ['bot_score <= 5', 'ja3:abc'],
        );

        $this->assertTrue($rule->evaluate($this->request(['X-Renamed-Score' => '2'])));
        $this->assertTrue(
            $rule->evaluate($this->request(['Cf-Ja3-Hash' => 'abc'])),
            'The signals that were not renamed keep the profile names.'
        );
    }

    /**
     * Everything the configuration can get wrong, and what it says about it.
     *
     * @param array<string, mixed> $metadata
     *   The rule's metadata.
     * @param string $expected
     *   Text the message has to contain.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('unusableConfigurations')]
    public function testAnUnusableConfigurationIsRefused(array $metadata, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/' . preg_quote($expected, '/') . '/');

        new EdgeSignal($metadata, ['bot_score <= 5']);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     *   Keyed by what is wrong with it.
     */
    public static function unusableConfigurations(): array
    {
        return [
            'an unknown provider' => [['provider' => 'akamai'], 'metadata.provider must be one of'],
            'a provider that is not a string' => [['provider' => 7], 'metadata.provider must be one of'],
            'headers that are not a map' => [
                ['provider' => 'cloudflare', 'headers' => 'Cf-Bot-Score'],
                'metadata.headers must be a map',
            ],
            'a header name that is empty' => [
                ['provider' => 'cloudflare', 'headers' => ['bot_score' => '  ']],
                'must be signal: "Header-Name" pairs',
            ],
            'an unknown signal' => [
                ['provider' => 'cloudflare', 'headers' => ['threat_score' => 'Cf-Threat-Score']],
                'unknown signal "threat_score"',
            ],
            'custom with nothing mapped' => [
                ['provider' => 'custom'],
                'names no headers',
            ],
        ];
    }

    /**
     * A misspelled signal is reported, not left to match nothing.
     */
    public function testAMisspelledSignalIsReported(): void
    {
        $handler = $this->captureLogs();

        new EdgeSignal(['provider' => 'cloudflare'], ['bot_scores <= 5']);

        $this->assertTrue($handler->hasWarningContaining('will not match anything'));
    }

    /**
     * It says what it is, for a log line and the rule inventory.
     */
    public function testItNamesItself(): void
    {
        $rule = new EdgeSignal(['provider' => 'cloudflare'], []);

        $this->assertSame('Edge Signals', $rule->getName());
        $this->assertStringContainsString('bot score', $rule->getDescription());
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
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        return $request;
    }

    /**
     * Collect log records for the duration of a test.
     */
    private function captureLogs(): TestLogHandler
    {
        $handler = new TestLogHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('edge', [$handler]));

        return $handler;
    }
}
