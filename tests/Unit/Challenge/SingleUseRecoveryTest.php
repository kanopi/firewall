<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\ChallengeProviderFactory;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\SingleUseSolutionInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * A refused submission must leave the visitor a way forward.
 *
 * When a provider's solution is spent by the attempt that posts it, the
 * interstitial cannot simply show an error and wait: the payload sitting in
 * the page is dead, so clicking Continue again re-posts something that
 * cannot succeed by construction. One failure then becomes a permanent
 * lockout, escapable only by a reload the page never suggests (#158).
 *
 * `InterstitialRenderer` provides the hook — `submit_failure`, run inside
 * `fail()` — and Turnstile and reCAPTCHA both use it. ALTCHA shipped
 * without one.
 *
 * "Spent by the attempt" cannot be read off the type system. ALTCHA says so
 * by implementing `SingleUseSolutionInterface`, because the firewall is what
 * records its solutions; Turnstile and reCAPTCHA implement nothing, because
 * Cloudflare and Google burn the token themselves and answer
 * `timeout-or-duplicate` to a replay. Keying the rule off the interface
 * would therefore have covered ALTCHA alone and let the next
 * Turnstile-shaped provider ship the same lockout.
 *
 * So the rule is inverted: every built-in must render a recovery path unless
 * it is listed as exempt, with a reason. A provider added to
 * `ChallengeProviderFactory::BUILTINS` forces the decision rather than
 * defaulting to silence.
 */
final class SingleUseRecoveryTest extends AbstractTestCase
{
    private const SECRET = 'single-use-recovery-test-secret';

    /**
     * Options for the providers that refuse to construct without keys.
     *
     * Cloudflare's and Google's published always-pass test pairs; nothing
     * here reaches the network.
     *
     * @var array<string, array<string, string>>
     */
    private const OPTIONS = [
        'turnstile' => [
            'site_key' => '1x00000000000000000000AA',
            'secret_key' => '1x0000000000000000000000000000000AA',
        ],
        'recaptcha' => [
            'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
            'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
        ],
    ];

    /**
     * The line every provider gets for free, which recovers nothing on its
     * own — it only reveals the error message.
     */
    private const SHARED_FAIL_LINE = "err.classList.add('visible');";

    /**
     * Providers exempt from the rule, and why.
     *
     * Only a provider whose solution SURVIVES a refused attempt belongs
     * here. Adding to this list is a claim that a visitor can click
     * Continue a second time and get a different answer.
     *
     * @var array<string, string>
     */
    private const RECOVERY_EXEMPT = [
        'math' => 'the signed answer|exp state stays valid, so retyping is a genuine retry',
    ];

    /**
     * Every built-in that must render a recovery path.
     *
     * Read off the factory's own list, minus the exemptions, so a provider
     * added later is covered without touching this file.
     *
     * @return array<string, array{0: string}>
     */
    public static function providerRequiringRecoveryProvider(): array
    {
        $cases = [];

        foreach (self::builtInNames() as $name) {
            if (!isset(self::RECOVERY_EXEMPT[$name])) {
                $cases[$name] = [$name];
            }
        }

        return $cases;
    }

    #[DataProvider('providerRequiringRecoveryProvider')]
    public function testProviderOffersAWayOutOfAFailedSubmission(string $name): void
    {
        $recovery = $this->recoveryBody($this->render($name));

        $this->assertNotSame(
            '',
            $recovery,
            sprintf(
                'A %s solution is spent by the attempt that posts it, so clicking Continue '
                . 'again re-posts something that cannot succeed. Its interstitial must do '
                . 'something on failure — reset the widget, or fetch a new challenge — or '
                . 'one refusal locks the visitor out for good. If %s solutions genuinely '
                . 'survive a refusal, add it to RECOVERY_EXEMPT with the reason.',
                $name,
                $name
            )
        );
    }

    public function testTheExemptionListNamesOnlyProvidersThatSurviveARefusal(): void
    {
        // Guards the escape hatch: an exemption is only honest if a second
        // click can actually produce a different answer. A provider whose
        // solutions the firewall itself records cannot qualify.
        foreach (array_keys(self::RECOVERY_EXEMPT) as $name) {
            $this->assertNotInstanceOf(
                SingleUseSolutionInterface::class,
                self::build($name),
                sprintf('%s records its solutions as single-use — it cannot be exempt.', $name)
            );
        }
    }

    public function testAltchaFetchesAFreshChallengeRatherThanResettingTheWidget(): void
    {
        // The distinction matters. Turnstile resets because Cloudflare mints
        // it a new token. ALTCHA's challenge is embedded in this page, so a
        // reset re-solves the same one and posts the same spent payload —
        // only a new render carries a new challenge.
        $recovery = $this->recoveryBody($this->render('altcha'));

        $this->assertStringContainsString('window.location.replace(redirectTo)', $recovery);
        $this->assertStringNotContainsString('widget.reset()', $recovery);
    }

    public function testAltchaDisablesSubmitWhileTheNewChallengeLoads(): void
    {
        // Between the refusal and the new page there is a window in which
        // the button still points at a dead payload.
        $this->assertStringContainsString('submit.disabled = true', $this->recoveryBody($this->render('altcha')));
    }

    public function testAltchaReplacesAdviceThatCannotBeFollowed(): void
    {
        // The shared error message is "Verification failed. Please try
        // again." — which is exactly what the visitor must NOT do, since
        // trying again with the same payload is what cannot work.
        $html = $this->render('altcha');

        $this->assertStringContainsString('Verification failed. Please try again.', $html);
        $this->assertStringContainsString('err.textContent =', $this->recoveryBody($html));
    }

    public function testMathNeedsNoRecoveryBecauseItsStateSurvivesAFailure(): void
    {
        // Scopes the rule. The math challenge signs `answer|exp` into the
        // form and is not single-use, so a wrong answer leaves the state
        // valid and retyping is a genuine retry. Reloading it would throw
        // away a challenge that still works.
        $provider = self::build('math');
        $this->assertNotInstanceOf(SingleUseSolutionInterface::class, $provider);
        $this->assertSame('', $this->recoveryBody($this->render('math')));
    }

    /**
     * Everything `fail()` does beyond revealing the error message.
     *
     * Extracted from the rendered document rather than read off the parts
     * array, so this measures what a browser would actually run.
     */
    private function recoveryBody(string $html): string
    {
        $found = preg_match('/function fail\(\) \{(.*?)\n      \}/s', $html, $matches);
        $this->assertSame(1, $found, 'no fail() handler in the rendered interstitial');

        $body = str_replace(self::SHARED_FAIL_LINE, '', $matches[1]);

        return trim($body);
    }

    private function render(string $name): string
    {
        return self::build($name)->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/protected',
            'ttl' => '600',
            'header_name' => 'X-Firewall-Challenge',
        ]);
    }

    private static function build(string $name): ChallengeProviderInterface
    {
        return ChallengeProviderFactory::create(
            $name,
            new TokenManager(self::SECRET),
            self::OPTIONS[$name] ?? []
        );
    }

    /**
     * The factory's built-in short names.
     *
     * @return array<int, string>
     */
    private static function builtInNames(): array
    {
        /** @var array<string, class-string<ChallengeProviderInterface>> $builtins */
        $builtins = (new \ReflectionClassConstant(ChallengeProviderFactory::class, 'BUILTINS'))->getValue();

        return array_keys($builtins);
    }
}
