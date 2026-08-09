<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\InterstitialRenderer;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Escaping rules for the shared interstitial document.
 *
 * The regression these guard is a real lockout: the ALTCHA, Turnstile and
 * reCAPTCHA submit buttons all render disabled and are only enabled by the
 * inline script, so a value that breaks that script's syntax leaves the
 * visitor with no way to complete the challenge.
 */
final class InterstitialRendererTest extends AbstractTestCase
{
    private const SECRET = 'interstitial-test-secret';

    /** Google's published test keys -- never reach the network here. */
    private const RECAPTCHA_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

    private const RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    /**
     * Values that broke, or could break, the inline script when they were
     * escaped with htmlspecialchars() instead of encoded as JS literals.
     *
     * @return array<string, array{0: string}>
     */
    public static function hostileRedirectProvider(): array
    {
        return [
            'trailing backslash' => ['/secure\\'],
            'escaped quote attempt' => ['/secure\\"'],
            'double quote' => ['/secure"onerror="alert(1)'],
            'single quote' => ["/secure'+alert(1)+'"],
            'script close tag' => ['/secure</script><script>alert(1)</script>'],
            'newline attempt' => ["/secure\\n+alert(1)"],
            'backslash run' => ['/secure\\\\\\'],
            'invalid utf8' => ["/secure\xC3\x28"],
        ];
    }

    #[DataProvider('hostileRedirectProvider')]
    public function testMathInterstitialStaysSyntacticallyValid(string $redirect): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirect,
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        $this->assertInlineScriptParses($html);
    }

    #[DataProvider('hostileRedirectProvider')]
    public function testAltchaInterstitialStaysSyntacticallyValid(string $redirect): void
    {
        $provider = new AltchaChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirect,
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        $this->assertInlineScriptParses($html);
    }

    #[DataProvider('hostileRedirectProvider')]
    public function testTurnstileInterstitialStaysSyntacticallyValid(string $redirect): void
    {
        $provider = new TurnstileChallengeProvider([
            'site_key' => '1x00000000000000000000AA',
            'secret_key' => '1x0000000000000000000000000000000AA',
        ]);
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirect,
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        $this->assertInlineScriptParses($html);
    }

    #[DataProvider('hostileRedirectProvider')]
    public function testRecaptchaV2InterstitialStaysSyntacticallyValid(string $redirect): void
    {
        $provider = new RecaptchaChallengeProvider([
            'site_key' => self::RECAPTCHA_SITE_KEY,
            'secret_key' => self::RECAPTCHA_SECRET_KEY,
        ]);
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirect,
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        $this->assertInlineScriptParses($html);
    }

    /**
     * v3 renders a different interstitial to v2 -- no checkbox widget, a
     * `grecaptcha.execute()` call instead -- so it needs its own case.
     */
    #[DataProvider('hostileRedirectProvider')]
    public function testRecaptchaV3InterstitialStaysSyntacticallyValid(string $redirect): void
    {
        $provider = new RecaptchaChallengeProvider([
            'version' => 'v3',
            'site_key' => self::RECAPTCHA_SITE_KEY,
            'secret_key' => self::RECAPTCHA_SECRET_KEY,
        ]);
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => $redirect,
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        $this->assertInlineScriptParses($html);
    }

    #[DataProvider('hostileRedirectProvider')]
    public function testHeaderNameIsAlsoJsEncoded(string $headerName): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/',
            'ttl' => '60',
            'header_name' => $headerName,
        ]);

        $this->assertInlineScriptParses($html);
    }

    public function testEscapeJsNeutralisesScriptClose(): void
    {
        $encoded = InterstitialRenderer::escapeJs('</script><script>alert(1)</script>');

        $this->assertStringNotContainsString('</script>', $encoded);
        $this->assertStringNotContainsString('<', $encoded);
        $this->assertStringNotContainsString('>', $encoded);
    }

    public function testEscapeJsEmitsAQuotedLiteral(): void
    {
        // The template interpolates the result bare, so the quotes must
        // come from the encoder itself.
        $encoded = InterstitialRenderer::escapeJs('/plain');

        $this->assertSame('"\/plain"', $encoded);
    }

    public function testEscapeJsNeverEmitsAnEmptyExpression(): void
    {
        $this->assertNotSame('', InterstitialRenderer::escapeJs("\xC3\x28"));
        $this->assertNotSame('', InterstitialRenderer::escapeJs(''));
    }

    public function testHtmlContextStillEscapesTheRedirectField(): void
    {
        $provider = new MathChallengeProvider(new TokenManager(self::SECRET));
        $html = $provider->renderInterstitial($this->getRequest('10.0.0.5'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/"><script>alert(1)</script>',
            'ttl' => '60',
            'header_name' => 'X-FW',
        ]);

        // The hidden input must not be breakable out of.
        $this->assertStringNotContainsString('"><script>alert(1)', $html);
        $this->assertStringContainsString('&lt;script&gt;', $html);
    }

    /**
     * Assert every inline (non-module) script in the document parses.
     *
     * Matches `<script>` with no attributes, so external bundles
     * (`<script src=... async defer>`) and module scripts are excluded --
     * only the markup this library generates is checked.
     *
     * Every block is checked, not just the first. Turnstile and reCAPTCHA v2
     * emit two: the document-bottom `(function ...)` block, and a second one
     * in `extra_head` declaring the widget callbacks. That second block is
     * what re-enables the submit button, so skipping it would leave the
     * lockout path this test exists to guard entirely unchecked.
     *
     * Uses node so this is a real parse rather than a regex approximation.
     */
    private function assertInlineScriptParses(string $html): void
    {
        $found = preg_match_all('#<script>(.*?)</script>#s', $html, $matches);
        $this->assertGreaterThan(0, $found, 'no inline script block found');

        // A value that broke out of the element would close one <script>
        // early and open another, so the tags stop balancing. Counted over
        // the whole document because that is where the imbalance shows up:
        // the captured blocks cannot contain `</script>` by construction,
        // the non-greedy match having stopped at the first one.
        $this->assertSame(
            preg_match_all('#<script[\s>]#', $html),
            preg_match_all('#</script>#', $html),
            'unbalanced <script> tags -- a rendered value escaped the element'
        );

        $node = trim((string) shell_exec('command -v node 2>/dev/null'));
        if ($node === '') {
            // Skipping is right locally, where node is optional. On CI it is
            // how this guard silently stopped running for 32 cases, so fail
            // instead: a future image change surfaces immediately rather
            // than quietly reverting to a green build that checks nothing.
            if (getenv('CI') !== false) {
                $this->fail('node is required to parse-check inline scripts on CI, and was not found');
            }

            $this->markTestSkipped('node is not available to parse-check the inline script');
        }

        foreach ($matches[1] as $index => $script) {
            $file = tempnam(sys_get_temp_dir(), 'fw-inline-') . '.js';
            file_put_contents($file, $script);

            $output = [];
            $status = 0;
            exec(escapeshellarg($node) . ' --check ' . escapeshellarg($file) . ' 2>&1', $output, $status);
            unlink($file);

            $this->assertSame(
                0,
                $status,
                "inline script block {$index} failed to parse:\n" . implode("\n", $output)
            );
        }
    }
}
