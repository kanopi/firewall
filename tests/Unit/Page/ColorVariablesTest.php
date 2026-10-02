<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Page;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Page\BlockPage;
use Kanopi\Firewall\Page\PageRenderer;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * The built-in pages are themed through custom properties, not selectors (#454).
 *
 * Every colour lives in `PageRenderer::COLORS`, so `:root { --fw-accent: … }` recolours
 * every rule that uses it, on the challenge, block and lockdown pages alike. These tests
 * keep it that way: a colour written straight into a rule fails them.
 */
final class ColorVariablesTest extends AbstractTestCase
{
    private const CONTEXT = [
        'submit_url' => '/_firewall/challenge',
        'redirect_to' => '/gated',
        'ttl' => '60',
        'header_name' => '',
        'notices' => ['A notice, so its rules are on the page.'],
    ];

    /**
     * Every built-in page.
     *
     * @return array<string, array{\Closure(): string}>
     */
    public static function pages(): array
    {
        $request = Request::create('/gated');

        return [
            'math' => [static fn(): string => (new MathChallengeProvider(new TokenManager('s')))->renderInterstitial($request, self::CONTEXT)],
            'altcha' => [static fn(): string => (new AltchaChallengeProvider(new TokenManager('s')))->renderInterstitial($request, self::CONTEXT)],
            'turnstile' => [static fn(): string => (new TurnstileChallengeProvider([
                'site_key' => '1x00000000000000000000AA',
                'secret_key' => '1x0000000000000000000000000000000AA',
            ]))->renderInterstitial($request, self::CONTEXT)],
            'recaptcha v2' => [static fn(): string => (new RecaptchaChallengeProvider([
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ]))->renderInterstitial($request, self::CONTEXT)],
            'recaptcha v3' => [static fn(): string => (new RecaptchaChallengeProvider([
                'version' => 'v3',
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ]))->renderInterstitial($request, self::CONTEXT)],
            'block' => [static fn(): string => BlockPage::html('block', BlockPage::DEFAULTS['block'], [])],
            'lockdown' => [static fn(): string => BlockPage::html('lockdown', BlockPage::DEFAULTS['lockdown'], [])],
        ];
    }

    /**
     * The page's built-in CSS, with the `:root` rule declaring the colours removed.
     */
    private static function rules(string $html): string
    {
        self::assertSame(1, preg_match('#<style>(.*?)</style>#s', $html, $style));

        return str_replace(PageRenderer::rootRule(), '', $style[1]);
    }

    /**
     * No rule names a colour itself.
     *
     * @param \Closure(): string $page
     */
    #[DataProvider('pages')]
    public function testNoRuleHardcodesAColour(\Closure $page): void
    {
        $rules = self::rules($page());

        self::assertDoesNotMatchRegularExpression('/[:\s,(]#[0-9a-fA-F]{3,8}\b/', $rules, 'A hex colour outside COLORS');
        self::assertDoesNotMatchRegularExpression('/\b(?:rgba?|hsla?)\s*\(/i', $rules, 'A functional colour outside COLORS');
    }

    /**
     * Every property a page uses is declared, and declared before it is used.
     *
     * @param \Closure(): string $page
     */
    #[DataProvider('pages')]
    public function testEveryPropertyUsedIsDeclaredFirst(\Closure $page): void
    {
        $html = $page();

        preg_match_all('/var\((--fw-[a-z-]+)\)/', $html, $used);

        self::assertNotSame([], $used[1]);
        self::assertSame([], array_diff(array_unique($used[1]), array_keys(PageRenderer::COLORS)), 'Used but not declared');
        self::assertLessThan(strpos($html, 'var(--fw-'), strpos($html, PageRenderer::rootRule()));
    }

    /**
     * Every declared property is used by some page, so none is a name that does nothing.
     */
    public function testEveryDeclaredPropertyIsUsed(): void
    {
        $used = [];

        foreach (self::pages() as [$page]) {
            preg_match_all('/var\((--fw-[a-z-]+)\)/', $page(), $matches);
            $used = [...$used, ...$matches[1]];
        }

        self::assertSame([], array_diff(array_keys(PageRenderer::COLORS), $used));
    }

    /**
     * The defaults are the colours the pages had before (#454 changes how they are
     * written, not what they are).
     */
    public function testTheDefaultsAreTheColoursThePagesAlwaysHad(): void
    {
        self::assertSame('#1f6feb', PageRenderer::COLORS['--fw-accent']);
        self::assertSame('#f5f6f8', PageRenderer::COLORS['--fw-bg']);
        self::assertSame('#b42318', PageRenderer::COLORS['--fw-error']);
        self::assertStringContainsString('--fw-accent: #1f6feb;', PageRenderer::rootRule());
    }

    /**
     * An operator's `:root` rule comes after the declarations, so it is the one that applies.
     */
    public function testAnOperatorsRootRuleWins(): void
    {
        $html = BlockPage::html('block', BlockPage::DEFAULTS['block'], ['styles' => ':root { --fw-accent: #0b8f5a; }']);

        $declared = strpos($html, PageRenderer::rootRule());
        $override = strpos($html, ':root { --fw-accent: #0b8f5a; }');

        self::assertNotFalse($declared);
        self::assertNotFalse($override);
        self::assertLessThan($override, $declared);
    }
}
