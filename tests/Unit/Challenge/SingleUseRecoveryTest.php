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
 * without one. These tests assert the rule rather than the instance, so the
 * next single-use provider cannot repeat it.
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
     * Built-in providers whose solutions are single-use.
     *
     * Read off the factory's own list so a provider added later is covered
     * without touching this file.
     *
     * @return array<string, array{0: string}>
     */
    public static function singleUseProviderProvider(): array
    {
        $cases = [];

        foreach (self::builtInNames() as $name) {
            if (self::build($name) instanceof SingleUseSolutionInterface) {
                $cases[$name] = [$name];
            }
        }

        return $cases;
    }

    #[DataProvider('singleUseProviderProvider')]
    public function testSingleUseProviderOffersAWayOutOfAFailedSubmission(string $name): void
    {
        $recovery = $this->recoveryBody($this->render($name));

        $this->assertNotSame(
            '',
            $recovery,
            sprintf(
                '%s solutions are single-use, so a retry re-posts a spent payload. Its '
                . 'interstitial must do something on failure — reset the widget, or fetch '
                . 'a new challenge — or one refusal locks the visitor out for good.',
                $name
            )
        );
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
