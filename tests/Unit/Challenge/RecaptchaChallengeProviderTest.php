<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Unit coverage for the Google reCAPTCHA provider.
 *
 * The network is the one thing these tests replace: `fetch()` is overridden
 * with scripted results, and the response handling it delegates to is
 * exercised directly through `interpretResponse()`. Nothing here reaches
 * Google.
 */
final class RecaptchaChallengeProviderTest extends AbstractTestCase
{
    /**
     * Google's documented always-passes v2 test pair.
     */
    private const SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

    private const SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    public function testGetNameReturnsRecaptchaOnV2(): void
    {
        $this->assertSame('recaptcha', $this->provider()->getName());
    }

    public function testGetNameIsVersionScopedOnV3(): void
    {
        // The name is what `challenge.audience` defaults to. A v3 pass is a
        // weaker claim than a v2 one, so the two must not share an audience
        // — otherwise a v3-earned token opens a v2-protected route.
        $this->assertSame('recaptcha-v3', $this->provider(['version' => 'v3'])->getName());
    }

    public function testMissingSiteKeyFailsAtConstruction(): void
    {
        // A firewall that renders a keyless widget challenges every visitor
        // with something none of them can pass, so this has to be loud.
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/site_key/');

        new RecaptchaChallengeProvider(['secret_key' => self::SECRET_KEY]);
    }

    public function testMissingSecretKeyFailsAtConstruction(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/secret_key/');

        new RecaptchaChallengeProvider(['site_key' => self::SITE_KEY]);
    }

    public function testWhitespaceOnlyKeysAreTreatedAsMissing(): void
    {
        $this->expectException(ConfigurationException::class);

        new RecaptchaChallengeProvider(['site_key' => '   ', 'secret_key' => self::SECRET_KEY]);
    }

    public function testNonScalarKeyIsTreatedAsMissing(): void
    {
        $this->expectException(ConfigurationException::class);

        new RecaptchaChallengeProvider(['site_key' => ['nested'], 'secret_key' => self::SECRET_KEY]);
    }

    public function testUnknownVersionFallsBackToV2(): void
    {
        // v2 is the safe default: a visitor who fails can try again, which
        // is not true of v3.
        $this->assertSame('recaptcha', $this->provider(['version' => 'v9'])->getName());
    }

    public function testVersionIsCaseInsensitive(): void
    {
        $this->assertSame('recaptcha-v3', $this->provider(['version' => 'V3'])->getName());
    }

    // -------------------------------------------------------------------
    // Endpoints and the payload field
    // -------------------------------------------------------------------

    public function testSiteverifyDefaultsToGoogle(): void
    {
        $this->assertSame(
            RecaptchaChallengeProvider::GOOGLE_HOST . RecaptchaChallengeProvider::SITEVERIFY_PATH,
            $this->provider()->getSiteverifyEndpoint()
        );
    }

    public function testRecaptchaNetMovesBothTheWidgetAndSiteverify(): void
    {
        // Google's documented alternate domain, for networks where
        // google.com is unreachable. Both halves have to move together — a
        // widget the visitor can load is useless if this server cannot
        // verify what it produces.
        $provider = $this->provider(['use_recaptcha_net' => true]);

        $this->assertStringStartsWith(
            RecaptchaChallengeProvider::RECAPTCHA_NET_HOST,
            $provider->getSiteverifyEndpoint()
        );
        $this->assertStringContainsString(
            RecaptchaChallengeProvider::RECAPTCHA_NET_HOST . '/recaptcha/api.js',
            $this->render($provider)
        );
    }

    public function testRecaptchaNetOnlyAcceptsABooleanTrue(): void
    {
        // A truthy YAML string must not silently redirect verification to a
        // different host.
        $this->assertStringStartsWith(
            RecaptchaChallengeProvider::GOOGLE_HOST,
            $this->provider(['use_recaptcha_net' => 'yes'])->getSiteverifyEndpoint()
        );
    }

    public function testPayloadFieldIsGooglesOnV2(): void
    {
        $this->assertSame(
            RecaptchaChallengeProvider::PAYLOAD_FIELD,
            $this->provider()->getPayloadField()
        );
    }

    public function testPayloadFieldIsOurOwnOnV3(): void
    {
        // api.js injects hidden textareas named `g-recaptcha-response`. Two
        // same-named fields make FormData carry both values, and which one
        // wins is not something to stake a security check on.
        $this->assertSame(
            RecaptchaChallengeProvider::V3_PAYLOAD_FIELD,
            $this->provider(['version' => 'v3'])->getPayloadField()
        );
        $this->assertNotSame(
            RecaptchaChallengeProvider::PAYLOAD_FIELD,
            RecaptchaChallengeProvider::V3_PAYLOAD_FIELD
        );
    }

    // -------------------------------------------------------------------
    // Rendering — v2
    // -------------------------------------------------------------------

    public function testV2RenderProducesTheWidgetAndTheContractFields(): void
    {
        $html = $this->render($this->provider());

        $this->assertStringContainsString('<form', $html);
        $this->assertStringContainsString('action="/_firewall/challenge"', $html);
        $this->assertStringContainsString('class="g-recaptcha"', $html);
        $this->assertStringContainsString('data-sitekey="' . self::SITE_KEY . '"', $html);
        $this->assertStringContainsString('/recaptcha/api.js', $html);
        $this->assertStringContainsString(
            'name="' . RecaptchaChallengeProvider::REDIRECT_FIELD . '"',
            $html
        );
        $this->assertStringContainsString('name="' . RecaptchaChallengeProvider::TTL_FIELD . '"', $html);
        $this->assertStringContainsString('value="/wanted-page"', $html);
        $this->assertStringContainsString('value="900"', $html);
    }

    public function testV2RenderShipsTheSubmitButtonDisabled(): void
    {
        // Enabled only by the widget's success callback, so an empty token
        // cannot be posted.
        $this->assertMatchesRegularExpression(
            '/<button[^>]*\sdisabled/',
            $this->render($this->provider())
        );
    }

    public function testV2CallbacksAreDeclaredBeforeTheWidgetBundleLoads(): void
    {
        // The bundle is async: it can finish and invoke the callback before
        // a document-bottom script would have defined it, and a missing
        // callback leaves the button disabled with no way forward.
        $html = $this->render($this->provider());

        $callback = strpos($html, 'window.fwRecaptchaVerified');
        $bundle = strpos($html, '/recaptcha/api.js');

        $this->assertIsInt($callback);
        $this->assertIsInt($bundle);
        $this->assertLessThan($bundle, $callback);
    }

    public function testV2WiresTheExpiryCallback(): void
    {
        // v2 tokens go stale about two minutes after the checkbox is
        // ticked. Without this a visitor who reads the page first posts a
        // token Google answers `timeout-or-duplicate` to.
        $this->assertStringContainsString(
            'data-expired-callback="fwRecaptchaReset"',
            $this->render($this->provider())
        );
    }

    public function testV2FailedSubmissionRecyclesTheWidget(): void
    {
        $this->assertStringContainsString(
            'window.grecaptcha.reset()',
            $this->render($this->provider())
        );
    }

    public function testConfiguredThemeAndSizeAreRendered(): void
    {
        $html = $this->render($this->provider(['theme' => 'DARK', 'size' => 'Compact']));

        $this->assertStringContainsString('data-theme="dark"', $html);
        $this->assertStringContainsString('data-size="compact"', $html);
    }

    public function testUnknownThemeAndSizeFallBackToTheDefaults(): void
    {
        // reCAPTCHA has no `auto` theme, so an unknown value cannot be
        // passed through and must resolve to something real.
        $html = $this->render($this->provider(['theme' => 'auto', 'size' => 'invisible']));

        $this->assertStringContainsString('data-theme="light"', $html);
        $this->assertStringContainsString('data-size="normal"', $html);
    }

    public function testRenderEmitsNoIntegrityAttribute(): void
    {
        // Deliberate, and different from ALTCHA: api.js is unversioned and
        // bootstraps further scripts, so a pinned digest would block the
        // script the first time Google ships a change.
        $this->assertStringNotContainsString('integrity=', $this->render($this->provider()));
    }

    public function testRenderEscapesTheSiteKeyIntoTheAttribute(): void
    {
        $provider = $this->provider(['site_key' => '6Le" onload="alert(1)']);

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

    // -------------------------------------------------------------------
    // Rendering — v3
    // -------------------------------------------------------------------

    public function testV3RenderExecutesAndParksTheTokenInItsOwnField(): void
    {
        $html = $this->render($this->provider(['version' => 'v3']));

        $this->assertStringContainsString(
            'name="' . RecaptchaChallengeProvider::V3_PAYLOAD_FIELD . '"',
            $html
        );
        $this->assertStringContainsString('window.grecaptcha.execute(', $html);
        $this->assertStringNotContainsString('class="g-recaptcha"', $html);
    }

    public function testV3AppendsTheRenderParameterToTheBundle(): void
    {
        // grecaptcha.execute() only exists when api.js was loaded with
        // render=<site key>.
        $this->assertStringContainsString(
            '/recaptcha/api.js?render=' . rawurlencode(self::SITE_KEY),
            $this->render($this->provider(['version' => 'v3']))
        );
    }

    public function testV3PollsForTheBundleRatherThanTrustingLoadOrder(): void
    {
        // api.js is async and bootstraps further scripts, and unlike v2
        // there is no callback attribute to hang execution off.
        $this->assertStringContainsString('window.setTimeout(fwRecaptchaExecute', $this->renderV3());
    }

    public function testV3RefreshesTheTokenBeforeItExpires(): void
    {
        // v3 tokens expire about two minutes after minting. A visitor who
        // leaves the tab open would otherwise return to a token Google can
        // only answer `timeout-or-duplicate` to.
        $this->assertStringContainsString('window.setInterval(fwRecaptchaExecute, 90000)', $this->renderV3());
    }

    public function testV3EscapesTheSiteKeyForScriptContext(): void
    {
        // HTML entities are not decoded inside <script>, and a trailing
        // backslash would escape the closing quote and kill the whole
        // script — which on v3 is the only thing that enables the button.
        $html = $this->render($this->provider([
            'version' => 'v3',
            'site_key' => 'key-with-a-trailing-backslash\\',
        ]));

        $this->assertStringContainsString('var fwSiteKey = "key-with-a-trailing-backslash\\\\"', $html);
    }

    public function testV3DisablesTheButtonBeforeMintingAReplacementToken(): void
    {
        // The refused attempt spent the token and minting is asynchronous,
        // so leaving Continue live would let a second click re-post it.
        $html = $this->renderV3();

        $failure = strpos($html, 'submit.disabled = true;');
        $refresh = strpos($html, 'window.fwRecaptchaRefresh();');

        $this->assertIsInt($failure);
        $this->assertIsInt($refresh);
        $this->assertLessThan($refresh, $failure);
    }

    public function testV3RendersTheConfiguredAction(): void
    {
        $this->assertStringContainsString(
            'var fwAction = "admin_area"',
            $this->render($this->provider(['version' => 'v3', 'action' => 'admin_area']))
        );
    }

    // -------------------------------------------------------------------
    // widget_src overrides
    // -------------------------------------------------------------------

    public function testCustomWidgetSrcIsHonouredOnV2(): void
    {
        $html = $this->render($this->provider(['widget_src' => '/assets/recaptcha.js']));

        $this->assertStringContainsString('src="/assets/recaptcha.js"', $html);
        $this->assertStringNotContainsString('www.google.com/recaptcha/api.js', $html);
    }

    /**
     * Widget URLs and what the v3 render parameter should do to them.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function widgetSrcProvider(): array
    {
        return [
            'bare path gains a query string' => [
                '/assets/recaptcha.js',
                '/assets/recaptcha.js?render=' . self::SITE_KEY,
            ],
            'existing query string gains a parameter' => [
                '/assets/recaptcha.js?v=2',
                '/assets/recaptcha.js?v=2&amp;render=' . self::SITE_KEY,
            ],
            'an explicit render is left alone' => [
                '/assets/recaptcha.js?render=someone-elses-key',
                '/assets/recaptcha.js?render=someone-elses-key',
            ],
        ];
    }

    /**
     * @param string $configured
     *   The `widget_src` option as an operator would set it.
     * @param string $expected
     *   The src attribute the interstitial should carry, HTML-escaped.
     */
    #[DataProvider('widgetSrcProvider')]
    public function testV3AddsTheRenderParameterToACustomWidgetSrc(
        string $configured,
        string $expected
    ): void {
        // Proxying the bundle should not require knowing that v3 needs the
        // render parameter — but an operator who supplied one meant it.
        $html = $this->render($this->provider([
            'version' => 'v3',
            'widget_src' => $configured,
        ]));

        $this->assertStringContainsString('src="' . $expected . '"', $html);
    }

    // -------------------------------------------------------------------
    // Verification — shared
    // -------------------------------------------------------------------

    public function testMissingTokenIsRejectedWithoutAskingGoogle(): void
    {
        $provider = $this->scriptedProvider([]);

        $this->assertFalse($provider->verifySolution($this->submission('')));
        $this->assertSame(0, $provider->fetchCount, 'An absent token cannot be valid — do not spend a round trip.');
    }

    public function testOverlongTokenIsRejectedWithoutAskingGoogle(): void
    {
        $provider = $this->scriptedProvider([]);

        $this->assertFalse($provider->verifySolution($this->submission(str_repeat('a', 8193))));
        $this->assertSame(0, $provider->fetchCount);
    }

    public function testArrayTokenIsRejectedWithoutThrowing(): void
    {
        // `InputBag::get()` raises BadRequestException on a non-scalar, and
        // verifySolution() is contractually forbidden from throwing, so
        // `g-recaptcha-response[]=x` must be an ordinary rejection.
        $provider = $this->scriptedProvider([]);

        $request = Request::create(
            '/_firewall/challenge',
            'POST',
            [RecaptchaChallengeProvider::PAYLOAD_FIELD => ['nested']],
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
        // Replay protection lives at Google, which is why this provider
        // needs no SingleUseSolutionInterface and touches no storage.
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
        // `allow` is about not locking visitors out during an outage. It
        // must never turn a token Google actively rejected into a pass.
        $provider = $this->scriptedProvider(
            [self::refused(['invalid-input-response'])],
            ['on_error' => 'allow']
        );

        $this->assertFalse($provider->verifySolution($this->submission('a-plausible-token')));
    }

    // -------------------------------------------------------------------
    // Verification — v3 gates
    // -------------------------------------------------------------------

    public function testV3AcceptsAScoreAtOrAboveTheThreshold(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.5, 'firewall')],
            ['version' => 'v3']
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testV3RefusesAScoreBelowTheThreshold(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.4, 'firewall')],
            ['version' => 'v3']
        );

        $this->assertFalse($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testV3HonoursACustomThreshold(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.8, 'firewall')],
            ['version' => 'v3', 'min_score' => 0.9]
        );

        $this->assertFalse($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testV3RefusesATokenMintedForAnotherAction(): void
    {
        // A v3 token is minted by the site key, not by a page. Without this
        // check a token from any other reCAPTCHA call on the site — a
        // newsletter box, a search field — would clear the firewall too.
        $provider = $this->scriptedProvider(
            [self::scored(0.9, 'newsletter_signup')],
            ['version' => 'v3']
        );

        $this->assertFalse($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testV3RefusesAResponseCarryingNoScore(): void
    {
        // Means the configured keys are a v2 pair. Passing it would treat a
        // "well-formed token" as "trustworthy visitor", which is the whole
        // difference between the two versions.
        $provider = $this->scriptedProvider([self::verified()], ['version' => 'v3']);

        $this->assertFalse($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testV2IgnoresAScoreEntirely(): void
    {
        // A v2 yes is the whole answer; a stray score must not gate it.
        $provider = $this->scriptedProvider([self::scored(0.0, 'something-else')]);

        $this->assertTrue($provider->verifySolution($this->submission('a-plausible-token')));
    }

    public function testZeroScoreIsNotConfusedWithNoScore(): void
    {
        // 0.0 is the worst possible score and must not read as "absent".
        $result = $this->provider(['version' => 'v3'])->exposedInterpret(200, (string) json_encode([
            'success' => true,
            'score' => 0.0,
            'action' => 'firewall',
        ]));

        $this->assertSame(0.0, $result['score']);
    }

    // -------------------------------------------------------------------
    // min_score and action normalisation
    // -------------------------------------------------------------------

    public function testMinScoreAboveOneIsClamped(): void
    {
        // `min_score: 50` is a plausible mistake from someone thinking in
        // percentages, and an unclamped threshold above 1.0 would reject
        // every visitor forever.
        $provider = $this->scriptedProvider(
            [self::scored(1.0, 'firewall')],
            ['version' => 'v3', 'min_score' => 50]
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testNegativeMinScoreIsClamped(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.0, 'firewall')],
            ['version' => 'v3', 'min_score' => -5]
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testNonNumericMinScoreFallsBackToTheDefault(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.4, 'firewall')],
            ['version' => 'v3', 'min_score' => 'strict']
        );

        $this->assertFalse($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testActionIsFilteredToWhatGoogleWillEchoBack(): void
    {
        // Google drops anything outside alphanumerics, slashes and
        // underscores server-side. Filtering here means the value compared
        // against is the value that will come back — otherwise a stray
        // character fails every verification as an action mismatch.
        $provider = $this->scriptedProvider(
            [self::scored(0.9, 'adminarea')],
            ['version' => 'v3', 'action' => 'admin area!']
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testActionThatFiltersToNothingFallsBackToTheDefault(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.9, RecaptchaChallengeProvider::DEFAULT_ACTION)],
            ['version' => 'v3', 'action' => '!!!']
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    public function testNonScalarActionFallsBackToTheDefault(): void
    {
        $provider = $this->scriptedProvider(
            [self::scored(0.9, RecaptchaChallengeProvider::DEFAULT_ACTION)],
            ['version' => 'v3', 'action' => ['nested']]
        );

        $this->assertTrue($provider->verifySolution($this->v3Submission('a-plausible-token')));
    }

    // -------------------------------------------------------------------
    // The request body
    // -------------------------------------------------------------------

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

    public function testSecretKeyIsSentToGoogleButNeverRendered(): void
    {
        $provider = $this->provider();

        $this->assertStringContainsString(
            'secret=' . urlencode(self::SECRET_KEY),
            $provider->exposedRequestBody('a-token', $this->submission('a-token'))
        );
        $this->assertStringNotContainsString(self::SECRET_KEY, $this->render($provider));
    }

    public function testSecretKeyIsNeverRenderedOnV3Either(): void
    {
        $provider = $this->provider(['version' => 'v3']);

        $this->assertStringNotContainsString(self::SECRET_KEY, $this->render($provider));
    }

    // -------------------------------------------------------------------
    // Response interpretation
    // -------------------------------------------------------------------

    public function testSuccessResponseIsInterpretedAsVerified(): void
    {
        $result = $this->provider()->exposedInterpret(200, (string) json_encode([
            'success' => true,
            'challenge_ts' => '2026-08-04T00:00:00Z',
            'hostname' => 'example.com',
        ]));

        $this->assertTrue($result['verified']);
        $this->assertNull($result['transport_error']);
        $this->assertNull($result['score'], 'v2 responses carry no score.');
        $this->assertNull($result['action']);
    }

    public function testScoreAndActionAreCarriedThrough(): void
    {
        $result = $this->provider(['version' => 'v3'])->exposedInterpret(200, (string) json_encode([
            'success' => true,
            'score' => 0.7,
            'action' => 'firewall',
        ]));

        $this->assertSame(0.7, $result['score']);
        $this->assertSame('firewall', $result['action']);
    }

    public function testMalformedScoreAndActionAreNotTrusted(): void
    {
        $result = $this->provider(['version' => 'v3'])->exposedInterpret(200, (string) json_encode([
            'success' => true,
            'score' => ['nested'],
            'action' => 42,
        ]));

        $this->assertNull($result['score']);
        $this->assertNull($result['action']);
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

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /**
     * A provider with the protected seams exposed for assertions.
     *
     * @param array<string, mixed> $options
     *   Options merged over valid defaults.
     */
    private function provider(array $options = []): RecaptchaChallengeProvider
    {
        $options += ['site_key' => self::SITE_KEY, 'secret_key' => self::SECRET_KEY];

        return new class ($options) extends RecaptchaChallengeProvider {
            /**
             * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
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
     * @param array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}> $results
     *   Results to return from successive fetch() calls, in order.
     * @param array<string, mixed> $options
     *   Options merged over valid defaults.
     */
    private function scriptedProvider(array $results, array $options = []): RecaptchaChallengeProvider
    {
        $options += ['site_key' => self::SITE_KEY, 'secret_key' => self::SECRET_KEY];

        return new class ($options, $results) extends RecaptchaChallengeProvider {
            /**
             * How many times siteverify would have been called.
             */
            public int $fetchCount = 0;

            /**
             * Remaining scripted results.
             *
             * @var array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}>
             */
            private array $scripted;

            /**
             * @param array<string, mixed> $options
             *   Provider options.
             * @param array<int, array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}> $scripted
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
                    'score' => null,
                    'action' => null,
                ];
            }
        };
    }

    /**
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    private static function verified(): array
    {
        return [
            'verified' => true,
            'error_codes' => [],
            'transport_error' => null,
            'score' => null,
            'action' => null,
        ];
    }

    /**
     * A v3 response Google said yes to, carrying a score and an action.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    private static function scored(float $score, string $action): array
    {
        return [
            'verified' => true,
            'error_codes' => [],
            'transport_error' => null,
            'score' => $score,
            'action' => $action,
        ];
    }

    /**
     * @param array<int, string> $codes
     *   Error codes Google returned.
     *
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    private static function refused(array $codes): array
    {
        return [
            'verified' => false,
            'error_codes' => $codes,
            'transport_error' => null,
            'score' => null,
            'action' => null,
        ];
    }

    /**
     * @return array{verified: bool, error_codes: array<int, string>, transport_error: string|null, score: float|null, action: string|null}
     */
    private static function unreachable(): array
    {
        return [
            'verified' => false,
            'error_codes' => [],
            'transport_error' => 'could not reach the reCAPTCHA siteverify API',
            'score' => null,
            'action' => null,
        ];
    }

    /**
     * Render an interstitial with a stock context.
     */
    private function render(
        RecaptchaChallengeProvider $provider,
        string $redirectTo = '/wanted-page'
    ): string {
        return $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirectTo,
            'ttl' => '900',
            'cookie_name' => 'fw_pass',
            'header_name' => 'X-FW',
        ]);
    }

    /**
     * A stock v3 interstitial.
     */
    private function renderV3(): string
    {
        return $this->render($this->provider(['version' => 'v3']));
    }

    private function submission(string $token): Request
    {
        return $this->post(RecaptchaChallengeProvider::PAYLOAD_FIELD, $token);
    }

    private function v3Submission(string $token): Request
    {
        return $this->post(RecaptchaChallengeProvider::V3_PAYLOAD_FIELD, $token);
    }

    private function post(string $field, string $token): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            [$field => $token],
            [],
            [],
            ['REMOTE_ADDR' => '10.0.0.5']
        );
    }
}
