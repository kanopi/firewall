<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

require_once __DIR__ . '/../../Traits/ChallengeNamespaceOverrides.php';

use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\TestLogHandler;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Level;
use Monolog\Logger;
use Symfony\Component\HttpFoundation\Request;

/**
 * The Turnstile siteverify transport, with the stream wrapper shimmed.
 *
 * `TurnstileChallengeProviderTest` and the integration suite both substitute
 * `fetch()` so the provider's decision logic can be tested without a network.
 * That is the right split, but it leaves the transport itself unexercised —
 * the unreachable endpoint, and reading back a response whose headers carry
 * no status line — and those are exactly the paths that decide whether a
 * Cloudflare outage locks every challenged route or waves everyone through.
 *
 * Reaching them against the live endpoint would need a real secret key in CI
 * and Cloudflare failing on demand, so the stream wrapper is shimmed instead.
 * See tests/Traits/ChallengeNamespaceOverrides.php.
 */
final class TurnstileTransportTest extends AbstractTestCase
{
    private const SITE_KEY = '1x00000000000000000000AA';

    private const SECRET_KEY = '1x0000000000000000000000000000000AA';

    /**
     * {@inheritdoc}
     */
    protected function tearDown(): void
    {
        // These are process-global. A leaked flag would feed a canned HTTP
        // response to every later test in the run.
        $GLOBALS['fake_challenge_http_response'] = null;
        $GLOBALS['fake_challenge_http_handles'] = [];

        parent::tearDown();
    }

    /**
     * A genuine token verified over the real transport.
     */
    public function testVerifiedTokenPassesThroughTheTransport(): void
    {
        $this->fakeResponse(200, (string) json_encode(['success' => true]));

        $this->assertTrue($this->provider()->verifySolution($this->submission()));
    }

    /**
     * Cloudflare's rejection is read back as a plain failure.
     */
    public function testRejectedTokenFailsThroughTheTransport(): void
    {
        $this->fakeResponse(200, (string) json_encode([
            'success' => false,
            'error-codes' => ['timeout-or-duplicate'],
        ]));

        $handler = $this->captureLogs();

        $this->assertFalse($this->provider()->verifySolution($this->submission()));
        $this->assertFalse(
            $handler->hasErrorContaining('could not be completed'),
            'A token Cloudflare answered about is a verdict, not a transport failure.',
        );
    }

    /**
     * An unreachable siteverify endpoint blocks by default.
     *
     * Fail-closed is the deliberate choice here, unlike the reputation
     * lookups: an attacker who can disrupt siteverify would otherwise get a
     * bypass for every challenged route on demand.
     */
    public function testUnreachableEndpointBlocksByDefault(): void
    {
        $GLOBALS['fake_challenge_http_response'] = false;

        $handler = $this->captureLogs();

        $this->assertFalse($this->provider()->verifySolution($this->submission()));
        $this->assertTrue(
            $handler->hasErrorContaining('Turnstile verification could not be completed'),
            'Locking visitors out has to be stated in the log, not inferred from a failed solve.',
        );
    }

    /**
     * The same outage lets visitors through under `on_error: allow`.
     */
    public function testUnreachableEndpointAllowsWhenConfiguredTo(): void
    {
        $GLOBALS['fake_challenge_http_response'] = false;

        $this->assertTrue(
            $this->provider(['on_error' => 'allow'])->verifySolution($this->submission())
        );
    }

    /**
     * A response the wrapper reported no headers for is a transport failure.
     *
     * Without `wrapper_data` there is no status line to read, so the body
     * cannot be trusted as a verdict however well-formed it looks — treating
     * it as one would turn a broken proxy into a free pass.
     */
    public function testResponseWithoutWrapperHeadersIsATransportFailure(): void
    {
        $GLOBALS['fake_challenge_http_response'] = [
            'body' => (string) json_encode(['success' => true]),
        ];

        $handler = $this->captureLogs();

        $this->assertFalse($this->provider()->verifySolution($this->submission()));
        $this->assertStringContainsString('unreadable status', $this->loggedTransportError($handler));
    }

    /**
     * A non-200 from siteverify is an outage, not a failed visitor.
     */
    public function testServerErrorFromSiteverifyIsATransportFailure(): void
    {
        $this->fakeResponse(503, '');

        $handler = $this->captureLogs();

        $this->assertFalse($this->provider()->verifySolution($this->submission()));
        $this->assertStringContainsString('returned HTTP 503', $this->loggedTransportError($handler));
    }

    /**
     * With `send_remoteip` on, the client IP reaches the wire.
     *
     * `buildRequestBody()` is unit-tested directly, but only the transport
     * proves the body it builds is what gets sent — an opt-in that never
     * left the process would look identical from the outside.
     */
    public function testRemoteIpOptInReachesTheRequestBody(): void
    {
        $this->fakeResponse(200, (string) json_encode(['success' => true]));

        $provider = new class (['site_key' => self::SITE_KEY, 'secret_key' => self::SECRET_KEY, 'send_remoteip' => true]) extends TurnstileChallengeProvider {
            public string $sent = '';

            /**
             * {@inheritdoc}
             */
            protected function buildRequestBody(string $token, Request $request): string
            {
                return $this->sent = parent::buildRequestBody($token, $request);
            }
        };

        $this->assertTrue($provider->verifySolution($this->submission()));
        $this->assertStringContainsString('remoteip=203.0.113.45', $provider->sent);
    }

    /**
     * Install a canned HTTP response with a conventional status line.
     */
    private function fakeResponse(int $status, string $body): void
    {
        $GLOBALS['fake_challenge_http_response'] = [
            'headers' => ['HTTP/1.1 ' . $status . ' ' . ($status === 200 ? 'OK' : 'Error')],
            'body' => $body,
        ];
    }

    /**
     * The reason recorded alongside a transport failure.
     *
     * `verifySolution()` logs one message for every unreachable verdict and
     * puts the specific reason in the context, so asserting on the message
     * alone cannot tell a 503 apart from a DNS failure — which is the whole
     * point of recording it.
     */
    private function loggedTransportError(TestLogHandler $handler): string
    {
        foreach ($handler->records as $record) {
            if (str_contains((string) $record->message, 'could not be completed')) {
                return (string) ($record->context['error'] ?? '');
            }
        }

        return '';
    }

    private function captureLogs(): TestLogHandler
    {
        $handler = new TestLogHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        return $handler;
    }

    /**
     * @param array<string, mixed> $options
     *   Provider options; the keys are filled in.
     */
    private function provider(array $options = []): TurnstileChallengeProvider
    {
        $options['site_key'] ??= self::SITE_KEY;
        $options['secret_key'] ??= self::SECRET_KEY;

        return new TurnstileChallengeProvider($options);
    }

    /**
     * A POST carrying a plausible widget token.
     */
    private function submission(string $ip = '203.0.113.45'): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [TurnstileChallengeProvider::PAYLOAD_FIELD => str_repeat('t', 64)],
            [],
            [],
            ['REMOTE_ADDR' => $ip]
        );
    }
}
