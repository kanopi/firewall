<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Integration;

use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The lockout a host hits in `mode: exception` with a per-rule provider (#311).
 *
 * Reported from building `kanopi/firewall-symfony`, which is the first consumer of this
 * flow outside the repository. In `mode: exception` the host renders the interstitial, and
 * before 2.26.0 it had no supported way to produce the signed `provider_token`: the prefix
 * that is signed is a `private const`, the signer is `protected`, and `Firewall` is `final`
 * with a `protected` constructor and a `create()` that hard-codes `new self`.
 *
 * Rendering without that field does not degrade. The submission is verified by the
 * *default* provider, the minted pass token carries that provider's `prv` claim, the rule
 * that demanded the challenge refuses it, and the visitor is served the same interstitial
 * forever — with nothing on the path logged above `notice`.
 *
 * Driven end to end rather than asserted on the exception's shape, because the shape was
 * never the bug. The round trip closing is.
 */
class PerRuleProviderExceptionModeTest extends TestCase
{
    use FileTrait;

    private const SECRET = 'per-rule-provider-secret-value-long-enough';

    /**
     * The provider the rule names, which is not the configured default.
     */
    private const SECONDARY = \Kanopi\Firewall\Tests\Challenge\AlwaysVerifyingRecaptchaProvider::class;

    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir() . '/firewall_311_' . uniqid();

        if (!mkdir($this->tempDir, 0777, true)) {
            throw new \RuntimeException('Failed to create temp directory');
        }
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->tempDir);
        parent::tearDown();
    }

    /**
     * A rule naming its own provider is challenged by *that* provider, and the
     * exception carries what the host needs to say so.
     */
    public function testTheExceptionNamesTheRulesOwnProvider(): void
    {
        $firewall = $this->firewall();

        try {
            $firewall->evaluate($this->gatedRequest());
            $this->fail('Expected ChallengeRequiredException.');
        } catch (ChallengeRequiredException $e) {
            // `math` is the configured default; the rule asked for `secondary`.
            $this->assertSame(self::SECONDARY, $e->getProviderName());
            $this->assertNotNull($e->getProvider());
            $this->assertInstanceOf(self::SECONDARY, $e->getProvider());
        }
    }

    /**
     * The context is complete, and carries the field a host cannot produce.
     */
    public function testTheExceptionCarriesASignedProviderToken(): void
    {
        $firewall = $this->firewall();

        try {
            $firewall->evaluate($this->gatedRequest());
            $this->fail('Expected ChallengeRequiredException.');
        } catch (ChallengeRequiredException $e) {
            $context = $e->getRenderContext();

            foreach (['submit_url', 'redirect_to', 'ttl', 'cookie_name', 'header_name', 'provider_token'] as $key) {
                $this->assertArrayHasKey($key, $context, sprintf('The render context is missing %s.', $key));
            }

            $this->assertSame('/_firewall/challenge', $context['submit_url']);

            // name.signature — the half a host cannot reproduce, because the
            // signed prefix is private and the signer is protected on a final
            // class.
            $this->assertStringStartsWith(self::SECONDARY . '.', $context['provider_token']);
            $this->assertGreaterThan(
                strlen(self::SECONDARY) + 1,
                strlen($context['provider_token']),
                'The provider token carries no signature.'
            );
        }
    }

    /**
     * The one-line path renders, and renders that token into the page.
     */
    public function testRenderInterstitialProducesAPageCarryingTheToken(): void
    {
        $firewall = $this->firewall();
        $request = $this->gatedRequest();

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeRequiredException.');
        } catch (ChallengeRequiredException $e) {
            $html = $e->renderInterstitial($request);

            $this->assertStringContainsString('<form', $html);
            $this->assertStringContainsString($e->getRenderContext()['provider_token'], $html);
        }
    }

    /**
     * The round trip closes — which is the actual bug.
     *
     * Solve the challenge the way a host's visitor would, posting back the
     * `provider_token` the firewall supplied, and the minted pass token must be
     * scoped to the rule's provider. Before #311 it was scoped to the default,
     * so the next request to the same URL was challenged again, forever.
     */
    public function testSolvingTheChallengeSatisfiesTheRuleThatDemandedIt(): void
    {
        $firewall = $this->firewall();
        $request = $this->gatedRequest();

        $providerToken = null;

        try {
            $firewall->evaluate($request);
            $this->fail('Expected ChallengeRequiredException.');
        } catch (ChallengeRequiredException $e) {
            $providerToken = $e->getRenderContext()['provider_token'];
        }

        $submission = $this->submission([
            \Kanopi\Firewall\Challenge\ChallengeProviderInterface::PROVIDER_FIELD => $providerToken,
        ]);

        $token = null;

        try {
            $firewall->evaluate($submission);
            $this->fail('Expected ChallengeSolvedException.');
        } catch (ChallengeSolvedException $e) {
            $token = $e->getToken();
        }

        // The pass token must now satisfy the rule that asked for it.
        $returning = Request::create(
            '/gated',
            'GET',
            [],
            ['fw_challenge_pass' => $token],
            [],
            ['REMOTE_ADDR' => '203.0.113.9']
        );

        $this->assertTrue(
            $firewall->evaluate($returning),
            'The visitor solved the challenge the rule asked for and was challenged again — '
            . 'the token was scoped to the wrong provider.'
        );
    }

    /**
     * The lockout itself, kept as a test so it cannot come back.
     *
     * This is what a host was forced to do before #311: render the interstitial without a
     * `provider_token`, because there was no way to produce one. Without that field
     * `resolveSubmissionProvider()` falls back to the configured default, so the **wrong
     * provider** is asked to verify the solution and the visitor can never get past the
     * challenge the rule demanded.
     *
     * Which way it fails depends on the two providers involved, and both are lockouts:
     *
     * - **Different shapes**, as here — the default cannot read the payload, the submission
     *   is refused, and the visitor is sent back for another challenge they also cannot
     *   pass.
     * - **Same shape**, as in the original report — the default *verifies* it, mints a pass
     *   token scoped to itself, and the rule then refuses that token because it carries the
     *   wrong `prv` claim. The visitor holds a valid token and is challenged forever.
     *
     * Nothing throws that a host would notice, and nothing on the path logs above `notice`.
     * That is what made it worth a high-priority bug rather than a papercut.
     */
    public function testOmittingTheProviderTokenLocksTheVisitorOut(): void
    {
        $firewall = $this->firewall();

        // No PROVIDER_FIELD — exactly what a host could produce before the fix.
        try {
            $firewall->evaluate($this->submission());
            $this->fail(
                'The submission was accepted without a provider_token. Either the default-provider '
                . 'fallback changed, or this test no longer reproduces #311.'
            );
        } catch (ChallengeRequiredException $e) {
            $this->assertSame('Invalid challenge solution', $e->getMessage());
        }

        // And with it, the same payload closes the round trip — see
        // testSolvingTheChallengeSatisfiesTheRuleThatDemandedIt(). The field is
        // the whole difference.
    }

    /**
     * A refused submission still names the provider that refused it, so a host
     * can serve a fresh challenge rather than a dead retry.
     */
    public function testARefusedSubmissionStillCarriesTheProvider(): void
    {
        $firewall = $this->firewall();

        // No payload at all, so the provider refuses it. The point is what the
        // exception carries, not why it was refused.
        $submission = $this->submission([\Kanopi\Firewall\Challenge\RecaptchaChallengeProvider::PAYLOAD_FIELD => '']);

        try {
            $firewall->evaluate($submission);
            $this->fail('Expected ChallengeRequiredException on a wrong answer.');
        } catch (ChallengeRequiredException $e) {
            $this->assertNotNull($e->getProvider());
            $this->assertNotSame([], $e->getRenderContext());
            $this->assertArrayHasKey('provider_token', $e->getRenderContext());
        }
    }

    /**
     * Constructed without a provider, rendering says so rather than emitting a
     * broken page. Nothing in the firewall raises it that way; this is the
     * guard on the public constructor.
     */
    public function testRenderingWithoutAProviderIsRefused(): void
    {
        $this->expectException(\Kanopi\Firewall\Exception\ConfigurationException::class);

        (new ChallengeRequiredException('no provider'))->renderInterstitial($this->gatedRequest());
    }

    /**
     * The old two-argument signature still works, because it is public API.
     */
    public function testTheOriginalConstructorSignatureStillWorks(): void
    {
        $previous = new \RuntimeException('cause');
        $exception = new ChallengeRequiredException('Challenge required', $previous);

        $this->assertSame('Challenge required', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertNull($exception->getProvider());
        $this->assertSame('', $exception->getProviderName());
        $this->assertSame([], $exception->getRenderContext());
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    private function firewall(): Firewall
    {
        $file = $this->tempDir . '/config.yml';

        file_put_contents($file, Yaml::dump([
            'global' => ['mode' => 'exception'],
            'challenge' => [
                'provider' => 'math',
                'secret' => self::SECRET,
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'path' => '/_firewall/challenge',
                // The rule names a provider other than the default, which is
                // the whole condition for this bug. Registered by FQCN, as a
                // host would register a custom one; this subclass replaces the
                // siteverify round trip with a standing yes, so the test needs
                // no network.
                'provider_options' => [
                    self::SECONDARY => ['site_key' => 'test-site-key', 'secret_key' => 'test-secret-key'],
                ],
            ],
            'storage' => ['type' => 'Kanopi\Firewall\Storage\InMemoryStorage'],
            'plugins' => [
                [
                    'plugin' => 'Kanopi\Firewall\Plugins\Url',
                    'response' => 'challenge',
                    'enable' => true,
                    'metadata' => ['name' => 'gated', 'challenge_provider' => self::SECONDARY],
                    'config' => ['path:/gated'],
                ],
            ],
        ], 6, 2));

        return Firewall::create([$file]);
    }

    private function gatedRequest(): Request
    {
        return Request::create('/gated', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
    }

    /**
     * A submission POST to the challenge path.
     *
     * @param array<string, string> $fields
     *   Fields to merge over the defaults.
     *
     * @return Request
     *   The request.
     */
    private function submission(array $fields = []): Request
    {
        return Request::create(
            '/_firewall/challenge',
            'POST',
            $fields + [
                \Kanopi\Firewall\Challenge\RecaptchaChallengeProvider::PAYLOAD_FIELD => 'a-solved-payload',
                \Kanopi\Firewall\Challenge\ChallengeProviderInterface::REDIRECT_FIELD => '/gated',
                \Kanopi\Firewall\Challenge\ChallengeProviderInterface::TTL_FIELD => '600',
            ],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.9']
        );
    }
}
