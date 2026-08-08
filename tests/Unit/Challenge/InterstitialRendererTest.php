<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\InterstitialRenderer;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Escaping rules for the shared interstitial document.
 *
 * The regression these guard is a real lockout: the ALTCHA submit button
 * renders disabled and is only enabled by the inline script, so a value
 * that breaks that script's syntax leaves the visitor with no way to
 * complete the challenge.
 */
final class InterstitialRendererTest extends AbstractTestCase
{
    private const SECRET = 'interstitial-test-secret';

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
     * Uses node when available so this is a real parse rather than a
     * regex approximation; skips rather than silently passing when node
     * is absent.
     */
    private function assertInlineScriptParses(string $html): void
    {
        $this->assertSame(
            1,
            preg_match('#<script>\s*(\(function.*?)</script>#s', $html, $matches),
            'inline script block not found'
        );

        $script = $matches[1];

        // A bare `</script>` anywhere in the block would have ended the
        // element early in a real browser, regardless of JS validity.
        $this->assertStringNotContainsString('</script>', $script);

        $node = trim((string) shell_exec('command -v node 2>/dev/null'));
        if ($node === '') {
            $this->markTestSkipped('node is not available to parse-check the inline script');
        }

        $file = tempnam(sys_get_temp_dir(), 'fw-inline-') . '.js';
        file_put_contents($file, $script);

        $output = [];
        $status = 0;
        exec(escapeshellarg($node) . ' --check ' . escapeshellarg($file) . ' 2>&1', $output, $status);
        unlink($file);

        $this->assertSame(0, $status, "inline script failed to parse:\n" . implode("\n", $output));
    }
}
