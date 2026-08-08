<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit coverage for the Cloudflare Turnstile provider.
 *
 * The network is the one thing these tests replace: `fetch()` is overridden
 * with scripted results, and the response handling it delegates to is
 * exercised directly through `interpretResponse()`. Nothing here reaches
 * Cloudflare.
 */
final class TurnstileChallengeProviderTest extends AbstractTestCase
{
    private const SITE_KEY = '1x00000000000000000000AA';

    private const SECRET_KEY = '1x0000000000000000000000000000000AA';

    public function testGetNameReturnsTurnstile(): void
    {
        $this->assertSame('turnstile', $this->provider()->getName());
    }

    public function testMissingSiteKeyFailsAtConstruction(): void
    {
        // A firewall that renders a keyless widget challenges every visitor
        // with something none of them can pass, so this has to be loud.
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/site_key/');

        new TurnstileChallengeProvider(['secret_key' => self::SECRET_KEY]);
    }

    public function testMissingSecretKeyFailsAtConstruction(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/secret_key/');

        new TurnstileChallengeProvider(['site_key' => self::SITE_KEY]);
    }

    public function testWhitespaceOnlyKeysAreTreatedAsMissing(): void
    {
        $this->expectException(ConfigurationException::class);

        new TurnstileChallengeProvider(['site_key' => '   ', 'secret_key' => self::SECRET_KEY]);
    }

    public function testNonScalarKeyIsTreatedAsMissing(): void
    {
        $this->expectException(ConfigurationException::class);

        new TurnstileChallengeProvider(['site_key' => ['nested'], 'secret_key' => self::SECRET_KEY]);
    }

    public function testRenderProducesTheWidgetAndTheContractFields(): void
    {
        $html = $this->render($this->provider());

        $this->assertStringContainsString('<form', $html);
        $this->assertStringContainsString('action="/_firewall/challenge"', $html);
        $this->assertStringContainsString('class="cf-turnstile"', $html);
        $this->assertStringContainsString('data-sitekey="' . self::SITE_KEY . '"', $html);
        $this->assertStringContainsString(
            'src="' . TurnstileChallengeProvider::DEFAULT_WIDGET_SRC . '"',
            $html
        );
        $this->assertStringContainsString('name="' . TurnstileChallengeProvider::REDIRECT_FIELD . '"', $html);
        $this->assertStringContainsString('name="' . TurnstileChallengeProvider::TTL_FIELD . '"', $html);
        $this->assertStringContainsString('value="/wanted-page"', $html);
        $this->assertStringContainsString('value="900"', $html);
    }

    public function testRenderShipsTheSubmitButtonDisabled(): void
    {
        // Enabled only by the widget's success callback, so an empty token
        // cannot be posted.
        $this->assertMatchesRegularExpression('/<button[^>]*\sdisabled/', $this->render($this->provider()));
    }

    public function testCallbacksAreDeclaredBeforeTheWidgetBundleLoads(): void
    {
        // The bundle is async: it can finish and invoke the callback before
        // a document-bottom script would have defined it, and a missing
        // callback leaves the button disabled with no way forward. Ordering
        // is the whole defence, so assert it.
        $html = $this->render($this->provider());

        $callback = strpos($html, 'window.fwTurnstileVerified');
        $bundle = strpos($html, TurnstileChallengeProvider::DEFAULT_WIDGET_SRC);

        $this->assertIsInt($callback);
        $this->assertIsInt($bundle);
        $this->assertLessThan($bundle, $callback);
    }

    public function testCallbacksResolveTheButtonLazily(): void
    {
        // Declared in <head>, so they must not capture the element — it does
        // not exist yet at that point.
        $this->assertStringContainsString(
            "document.getElementById('submit')",
            $this->render($this->provider())
        );
    }

    public function testRenderEmitsNoIntegrityAttribute(): void
    {
        // Deliberate, and different from ALTCHA: Cloudflare's bundle URL is
        // unversioned and mutable, so a pinned digest would block the script
        // the first time they ship a change.
        $this->assertStringNotContainsString('integrity=', $this->render($this->provider()));
    }

    public function testRenderEscapesTheSiteKeyIntoTheAttribute(): void
    {
        $provider = $this->provider(['site_key' => '1x000" onload="alert(1)']);

        $html = $this->render($provider);

        $this->assertStringNotContainsString('onload="alert(1)"', $html);
        $this->assertStringContainsString('&quot;', $html);
    }

    public function testRenderEscapesContextValues(): void
    {
        $html = $this->render($this->provider(), '/"><script>alert(1)</script>');

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testConfiguredThemeIsRendered(): void
    {
        $this->assertStringContainsString(
            'data-theme="dark"',
            $this->render($this->provider(['theme' => 'DARK']))
        );
    }

    public function testUnknownThemeFallsBackToAuto(): void
    {
        $this->assertStringContainsString(
            'data-theme="auto"',
            $this->render($this->provider(['theme' => 'chartreuse']))
        );
    }

    public function testCustomWidgetSrcIsHonoured(): void
    {
        $html = $this->render($this->provider(['widget_src' => '/assets/turnstile.js']));

        $this->assertStringContainsString('src="/assets/turnstile.js"', $html);
        $this->assertStringNotContainsString(TurnstileChallengeProvider::DEFAULT_WIDGET_SRC, $html);
    }

    public function testFailedSubmissionRecyclesTheWidget(): void
    {
        // The attempt spends the token, so without a reset the visitor is
        // left clicking Continue on something Cloudflare will only ever
        // answer `timeout-or-duplicate` to.
        $this->assertStringContainsString('window.turnstile.reset()', $this->render($this->provider()));
    }

    public function testMissingTokenIsRejectedWithoutAskingCloudflare(): void
    {
        $provider = $this->scriptedProvider([]);

        $this->assertFalse($provider->verifySolution($this->submission('')));
        $this->assertSame(0, $provider->fetchCount, 'An absent token cannot be valid — do not spend a round trip.');
    }

    public function testOverlongTokenIsRejectedWithoutAskingCloudflare(): void
    {
        $provider = $this->scriptedProvider([]);

        $this->assertFalse($provider->verifySolution($this->submission(str_repeat('a', 2049))));
        $this->assertSame(0, $provider->fetchCount);
    }

    public function testArrayTokenIsRejectedWithoutThrowing(): void
    {
        // `InputBag::get()` raises BadRequestException on a non-scalar, and
        // verifySolution() is contractually forbidden from throwing, so
        // `cf-turnstile-response[]=x` must be an ordinary rejection.
        $provider = $this->scriptedProvider([]);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [TurnstileChallengeProvider::PAYLOAD_FIELD => ['nested']],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.5']
        );

        $this->assertFalse($provider->verifySolution($request));
        $this->assertSame(0, $provider->fetchCount);
    }

    public function testSuccessfulVerificationIsAccepted(): void
    {
        $provider = $this->scriptedProvider([self::verified()]);

        $this->assertTrue($provider->verifySolution($this->submission('a-plausible-token')));
        $this->assertSame(1, $provider->fetchCount);
    }

    public function testRejectedTokenIsRefused(): void
    {
        $provider = $this->scriptedProvider([self::refused(['invalid-input-response'])]);

        $this->assertFalse($provider->verifySolution($this->submission('a-plausible-token')));
    }

    public function testReplayedTokenIsRefused(): void
    {
        // Replay protection lives at Cloudflare, which is why this provider
        // needs no SingleUseSolutionInterface or storage record.
        $provider = $this->scriptedProvider([self::refused(['timeout-or-duplicate'])]);

        $this->assertFalse($provider->verifySolution($this->submission('a-replayed-token')));
    }

    public function testMisconfiguredSecretIsRefused(): void
    {
        $provider = $this->scriptedProvider([self::refused(['invalid-input-secret'])]);

        $this->assertFalse($provider->verifySolution($this->submission('a-plausible-token')));
    }

    public function testUnreachableSiteverifyBlocksByDefault(): void
    {
        $provider = $this->scriptedProvider([self::unreachable()]);

        $this->assertFalse(
            $provider->verifySolution($this->submission('a-plausible-token')),
            'Fail closed: a verdict that could not be obtained is not a pass.'
        );
    }

    public function testUnreachableSiteverifyAllowsWhenExplicitlyConfigured(): void
    {
        $provider = $this->scriptedProvider([self::unreachable()], ['on_error' => 'allow']);

        $this->assertTrue($provider->verifySolution($this->submission('a-plausible-token')));
    }

    public function testOnErrorOnlyAppliesToUnreachability(): void
    {
        // `allow` is about not locking visitors out during an outage. It must
        // never turn a token Cloudflare actively rejected into a pass.
        $provider = $this->scriptedProvider(
            [self::refused(['invalid-input-response'])],
            ['on_error' => 'allow']
        );

        $this->assertFalse($provider->verifySolution($this->submission('a-plausible-token')));
    }

    public function testClientIpIsWithheldByDefault(): void
    {
        // Behind an unconfigured proxy `getClientIp()` returns whatever
        // X-Forwarded-For claimed, so sending it can fail verification for
        // legitimate visitors. Opt-in only.
        $body = $this->provider()->exposedRequestBody('a-token', $this->submission('a-token'));

        $this->assertStringContainsString('response=a-token', $body);
        $this->assertStringNotContainsString('remoteip', $body);
    }

    public function testClientIpIsSentWhenOptedIn(): void
    {
        $body = $this->provider(['send_remoteip' => true])
            ->exposedRequestBody('a-token', $this->submission('a-token'));

        $this->assertStringContainsString('remoteip=10.0.0.5', $body);
    }

    public function testSendRemoteIpOnlyAcceptsABooleanTrue(): void
    {
        // A truthy YAML string must not silently enable it.
        $body = $this->provider(['send_remoteip' => 'yes'])
            ->exposedRequestBody('a-token', $this->submission('a-token'));

        $this->assertStringNotContainsString('remoteip', $body);
    }

    public function testSecretKeyIsSentToCloudflareButNeverRendered(): void
    {
        $provider = $this->provider();

        $this->assertStringContainsString(
            'secret=' . self::SECRET_KEY,
            $provider->exposedRequestBody('a-token', $this->submission('a-token'))
        );
        $this->assertStringNotContainsString(self::SECRET_KEY, $this->render($provider));
    }

    public function testSuccessResponseIsInterpretedAsVerified(): void
    {
        $result = $this->provider()->exposedInterpret(200, (string) json_encode([
            'success' => true,
            'challenge_ts' => '2026-08-04T00:00:00Z',
            'hostname' => 'example.com',
        ]));

        $this->assertTrue($result['verified']);
        $this->assertNull($result['transport_error']);
    }

    public function testFailureResponseCarriesItsErrorCodes(): void
    {
        $result = $this->provider()->exposedInterpret(200, (string) json_encode([
            'success' => false,
            'error-codes' => ['invalid-input-response'],
        ]));

        $this->assertFalse($result['verified']);
        $this->assertNull($result['transport_error'], 'A rejection is a verdict, not a transport failure.');
        $this->assertSame(['invalid-input-response'], $result['error_codes']);
    }

    public function testInternalErrorIsTreatedAsATransportFailure(): void
    {
        // Cloudflare documents internal-error as retryable, so it is not a
        // verdict on the token and `on_error` should govern it.
        $result = $this->provider()->exposedInterpret(200, (string) json_encode([
            'success' => false,
            'error-codes' => ['internal-error'],
        ]));

        $this->assertFalse($result['verified']);
        $this->assertNotNull($result['transport_error']);
    }

    /**
     * Responses that mean "no verdict available".
     *
     * @return array<string, array{0: int|null, 1: string|false}>
     */
    public static function noVerdictProvider(): array
    {
        return [
            'server error' => [500, '{"success":true}'],
            'gateway timeout' => [504, ''],
            'unparseable status' => [null, '{"success":true}'],
            'empty body' => [200, ''],
            'read failure' => [200, false],
            'not json' => [200, 'definitely not json'],
            'json but not an object' => [200, '"a string"'],
            'object without success' => [200, '{"error-codes":["bad-request"]}'],
        ];
    }

    /**
     * @param int|null $status
     *   HTTP status to interpret.
     * @param string|false $body
     *   Body to interpret.
     */
    #[DataProvider('noVerdictProvider')]
    public function testResponsesWithoutAVerdictAreTransportFailures(?int $status, string|false $body): void
    {
        $result = $this->provider()->exposedInterpret($status, $body);

        $this->assertFalse($result['verified']);
        $this->assertNotNull($result['transport_error']);
    }

    public function testSuccessOutsideAJsonBooleanIsNotAPass(): void
    {
        // A truthy-but-not-true value must not be read as verified.
        $result = $this->provider()->exposedInterpret(200, '{"success":"true"}');

        $this->assertFalse($result['verified']);
        $this->assertNull($result['transport_error']);
    }

    public function testMalformedErrorCodesAreNormalisedRatherThanTrusted(): void
    {
        $result = $this->provider()->exposedInterpret(200, (string) json_encode([
            'success' => false,
            'error-codes' => ['invalid-input-response', 42, ['nested'], null],
        ]));

        $this->assertSame(['invalid-input-response'], $result['error_codes']);
    }

    public function testNonArrayErrorCodesAreIgnored(): void
    {
        $result = $this->provider()->exposedInterpret(200, '{"success":false,"error-codes":"oops"}');

        $this->assertSame([], $result['error_codes']);
    }

    public function testStatusIsReadFromTheLastStatusLine(): void
    {
        // A redirect chain leaves several; the last one answered.
        $this->assertSame(200, $this->provider()->exposedStatus([
            'HTTP/1.1 301 Moved Permanently',
            'Location: https://example.com/',
            'HTTP/1.1 200 OK',
        ]));
    }

    public function testStatusIsNullWhenNoStatusLineIsPresent(): void
    {
        $this->assertNull($this->provider()->exposedStatus(['Content-Type: application/json']));
    }

    /**
     * A provider with the protected seams exposed for assertions.
     *
     * @param array<string, mixed> $options
     *   Options merged over valid defaults.
     */
    private function provider(array $options = []): TurnstileChallengeProvider
    {
        $options += ['site_key' => self::SITE_KEY, 'secret_key' => self::SECRET_KEY];

        return new class ($options) extends TurnstileChallengeProvider {
            /**
             * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
             */
            public function exposedInterpret(?int $status, string|false $body): array
            {
                return $this->interpretResponse($status, $body);
            }

            public function exposedRequestBody(string $token, Request $request): string
            {
                return $this->buildRequestBody($token, $request);
            }

            /**
             * @param array<int, string> $headers
             */
            public function exposedStatus(array $headers): ?int
            {
                return $this->statusFromHeaders($headers);
            }
        };
    }

    /**
     * A provider with the network replaced by scripted results.
     *
     * @param array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null}> $results
     *   Results to return from successive fetch() calls, in order.
     * @param array<string, mixed> $options
     *   Options merged over valid defaults.
     */
    private function scriptedProvider(array $results, array $options = []): TurnstileChallengeProvider
    {
        $options += ['site_key' => self::SITE_KEY, 'secret_key' => self::SECRET_KEY];

        return new class ($options, $results) extends TurnstileChallengeProvider {
            /**
             * How many times siteverify would have been called.
             */
            public int $fetchCount = 0;

            /**
             * Remaining scripted results.
             *
             * @var array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null}>
             */
            private array $scripted;

            /**
             * @param array<string, mixed> $options
             *   Provider options.
             * @param array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null}> $scripted
             *   Scripted fetch results.
             */
            public function __construct(array $options, array $scripted)
            {
                parent::__construct($options);
                $this->scripted = $scripted;
            }

            /**
             * {@inheritdoc}
             */
            protected function fetch(string $token, Request $request): array
            {
                $this->fetchCount++;

                $next = array_shift($this->scripted);

                return $next ?? [
                    'verified' => false,
                    'error_codes' => [],
                    'transport_error' => 'the test scripted no further results',
                ];
            }
        };
    }

    /**
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     */
    private static function verified(): array
    {
        return ['verified' => true, 'error_codes' => [], 'transport_error' => null];
    }

    /**
     * @param array<int, string> $codes
     *   Error codes Cloudflare returned.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     */
    private static function refused(array $codes): array
    {
        return ['verified' => false, 'error_codes' => $codes, 'transport_error' => null];
    }

    /**
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null}
     */
    private static function unreachable(): array
    {
        return [
            'verified' => false,
            'error_codes' => [],
            'transport_error' => 'could not reach the Turnstile siteverify API',
        ];
    }

    /**
     * Render an interstitial with a stock context.
     */
    private function render(TurnstileChallengeProvider $provider, string $redirectTo = '/wanted-page'): string
    {
        return $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirectTo,
            'ttl' => '900',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);
    }

    private function submission(string $token): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [TurnstileChallengeProvider::PAYLOAD_FIELD => $token],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.5']
        );
    }
}
