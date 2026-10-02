<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\AltchaChallengeProvider;
use Kanopi\Firewall\Challenge\ChallengePage;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * `challenge.page`: the wording, language and styling of the interstitial (#451).
 *
 * In `mode: block` the page is the library's, and its title, heading, button, language and
 * CSS were fixed. Changing any of them meant writing a provider.
 */
final class InterstitialPageTest extends AbstractTestCase
{
    private const SECRET = 'interstitial-page-test-secret';

    private const CONTEXT = [
        'submit_url' => '/_firewall/challenge',
        'redirect_to' => '/gated',
        'ttl' => '60',
        'header_name' => '',
    ];

    private const PAGE = [
        'lang' => 'fr-CA',
        'title' => 'Vérification requise',
        'heading' => 'Vérification rapide',
        'intro' => 'Merci de confirmer que vous êtes humain.',
        'button' => 'Continuer',
        'error_message' => 'La vérification a échoué.',
        'styles' => 'button { background: #0b5; }',
        'stylesheet' => '/themes/site/firewall.css',
    ];

    // -----------------------------------------------------------------------
    // The page
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{\Closure(): ChallengeProviderInterface}>
     */
    public static function providers(): array
    {
        return [
            'math' => [static fn(): ChallengeProviderInterface => new MathChallengeProvider(new TokenManager(self::SECRET))],
            'altcha' => [static fn(): ChallengeProviderInterface => new AltchaChallengeProvider(new TokenManager(self::SECRET))],
            'turnstile' => [static fn(): ChallengeProviderInterface => new TurnstileChallengeProvider([
                'site_key' => '1x00000000000000000000AA',
                'secret_key' => '1x0000000000000000000000000000000AA',
            ])],
            'recaptcha v2' => [static fn(): ChallengeProviderInterface => new RecaptchaChallengeProvider([
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ])],
            'recaptcha v3' => [static fn(): ChallengeProviderInterface => new RecaptchaChallengeProvider([
                'version' => 'v3',
                'site_key' => '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
                'secret_key' => '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
            ])],
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function render(ChallengeProviderInterface $provider, array $context): string
    {
        return $provider->renderInterstitial(Request::create('/gated', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.5']), $context);
    }

    /**
     * No page, the page it always was.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testNoPageKeepsTheBuiltInWording(\Closure $provider): void
    {
        $html = $this->render($provider(), self::CONTEXT);

        $this->assertStringContainsString('<html lang="en">', $html);
        $this->assertStringContainsString('<title>Verification required</title>', $html);
        $this->assertStringContainsString('<h1>Quick verification</h1>', $html);
        $this->assertStringContainsString('>Continue</button>', $html);
        $this->assertStringNotContainsString('<link rel="stylesheet"', $html);
    }

    /**
     * Every built-in page takes every key.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testEveryBuiltInPageTakesEveryKey(\Closure $provider): void
    {
        $html = $this->render($provider(), self::CONTEXT + ['page' => self::PAGE]);

        $this->assertStringContainsString('<html lang="fr-CA">', $html);
        $this->assertStringContainsString('<title>Vérification requise</title>', $html);
        $this->assertStringContainsString('<h1>Vérification rapide</h1>', $html);
        $this->assertStringContainsString('<p>Merci de confirmer que vous êtes humain.</p>', $html);
        $this->assertStringContainsString('>Continuer</button>', $html);
        $this->assertStringContainsString('role="alert">La vérification a échoué.</div>', $html);
        $this->assertStringContainsString('<link rel="stylesheet" href="/themes/site/firewall.css">', $html);

        $this->assertStringNotContainsString('Quick verification', $html);
        $this->assertStringNotContainsString('below to continue', $html, "The provider's own intro is replaced.");
    }

    /**
     * The operator's CSS comes after the built-in rules and the provider's, and the
     * stylesheet after the style block, so both win at equal specificity.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testTheOperatorsStylesComeLast(\Closure $provider): void
    {
        $html = $this->render($provider(), self::CONTEXT + ['page' => self::PAGE]);

        $builtIn = strpos($html, '.notice {');
        $styles = strpos($html, 'button { background: #0b5; }');
        $close = strpos($html, '</style>');
        $link = strpos($html, '<link rel="stylesheet"');

        $this->assertNotFalse($builtIn);
        $this->assertNotFalse($styles);
        $this->assertNotFalse($close);
        $this->assertNotFalse($link);
        $this->assertLessThan($styles, $builtIn);
        $this->assertLessThan($close, $styles);
        $this->assertLessThan($link, $close);
    }

    /**
     * Unset keys keep the provider's own intro and error message.
     */
    public function testUnsetKeysKeepTheProvidersOwnText(): void
    {
        $html = $this->render(
            new MathChallengeProvider(new TokenManager(self::SECRET)),
            self::CONTEXT + ['page' => ['heading' => 'Un instant']]
        );

        $this->assertStringContainsString('<h1>Un instant</h1>', $html);
        $this->assertStringContainsString('Please answer the question below to continue.', $html);
        $this->assertStringContainsString('Incorrect answer. Please try again.', $html);
        $this->assertStringContainsString('<title>Verification required</title>', $html);
    }

    /**
     * Text is plain text: whatever it holds, it never becomes markup.
     *
     * @param \Closure(): ChallengeProviderInterface $provider
     */
    #[DataProvider('providers')]
    public function testTextIsEscaped(\Closure $provider): void
    {
        $hostile = '<script>alert(1)</script> & "q"';
        $page = array_fill_keys(ChallengePage::TEXT_KEYS, $hostile);

        $html = $this->render($provider(), self::CONTEXT + ['page' => $page]);

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertSame(
            count(ChallengePage::TEXT_KEYS),
            substr_count($html, '&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;')
        );
    }

    /**
     * A context a host built is not trusted: values that would fail validation are left
     * out rather than written.
     */
    public function testAnUnvalidatedContextIsFilteredWhenThePageIsWritten(): void
    {
        $html = $this->render(new MathChallengeProvider(new TokenManager(self::SECRET)), self::CONTEXT + ['page' => [
            'lang' => 'en"><script>',
            'styles' => '</style><script>alert(1)</script>',
            'stylesheet' => 'javascript:alert(1)',
            'title' => ['not', 'text'],
            'unknown' => 'ignored',
        ]]);

        $this->assertStringContainsString('<html lang="en">', $html);
        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringNotContainsString('javascript:', $html);
        $this->assertStringContainsString('<title>Verification required</title>', $html);

        $this->assertSame([], ChallengePage::fromContext(['page' => 'not a map']));
        $this->assertSame([], ChallengePage::fromContext([]));
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    public function testNothingConfiguredIsNothing(): void
    {
        $this->assertSame([], ChallengePage::fromConfig(null));
        $this->assertSame([], ChallengePage::fromConfig([]));
    }

    /**
     * Set keys are kept and trimmed; empty and null ones mean unset.
     */
    public function testValidKeysAreKeptAndTrimmed(): void
    {
        $this->assertSame(
            ['lang' => 'zh-Hant-TW', 'title' => 'Hi', 'stylesheet' => 'https://cdn.example.com/fw.css'],
            ChallengePage::fromConfig([
                'lang' => ' zh-Hant-TW ',
                'title' => '  Hi ',
                'heading' => '   ',
                'button' => null,
                'stylesheet' => 'https://cdn.example.com/fw.css',
            ])
        );
    }

    /**
     * @return array<string, array{mixed, string}>
     */
    public static function unusable(): array
    {
        return [
            'not a map' => ['Verification', 'must be a map'],
            'an unknown key' => [['buton' => 'Go'], 'unknown key "buton"'],
            'text that is not text' => [['title' => 42], 'title must be text, not int'],
            'a list as text' => [['intro' => ['a', 'b']], 'intro must be text, not array'],
            'a malformed language' => [['lang' => 'english language'], 'lang must be a language tag'],
            'css closing its block' => [['styles' => 'p{} </style><script>x</script>'], 'must not contain "</style"'],
            'in any case' => [['styles' => '</STYLE >'], 'must not contain "</style"'],
            'a protocol-relative stylesheet' => [['stylesheet' => '//evil.example/x.css'], 'stylesheet must be'],
            'an http stylesheet' => [['stylesheet' => 'http://cdn.example.com/x.css'], 'stylesheet must be'],
            'a javascript: stylesheet' => [['stylesheet' => 'javascript:alert(1)'], 'stylesheet must be'],
            'a data: stylesheet' => [['stylesheet' => 'data:text/css,body{}'], 'stylesheet must be'],
            'a relative stylesheet' => [['stylesheet' => 'css/firewall.css'], 'stylesheet must be'],
            'a stylesheet with a quote' => [['stylesheet' => '/x.css" onload="alert(1)'], 'stylesheet must be'],
        ];
    }

    #[DataProvider('unusable')]
    public function testAnUnusableValueIsRefused(mixed $page, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($expected);

        ChallengePage::fromConfig($page);
    }

    /**
     * Every problem is reported, not only the first.
     */
    public function testEveryProblemIsReported(): void
    {
        $this->assertCount(3, ChallengePage::problems(['buton' => 'Go', 'title' => 1, 'lang' => '!!']));
        $this->assertSame([], ChallengePage::problems(self::PAGE));
    }

    // -----------------------------------------------------------------------
    // Through the firewall
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $challenge
     */
    private function firewall(array $challenge = []): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'challenge' => $challenge + ['provider' => 'math', 'secret' => self::SECRET, 'path' => '/_firewall/challenge'],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'enable' => true,
                'config' => ['path:/gated'],
            ]],
        ]]);
    }

    private function challenge(Firewall $firewall, ?Request $request = null): ChallengeRequiredException
    {
        try {
            $firewall->evaluate($request ?? Request::create('/gated', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
        } catch (ChallengeRequiredException $exception) {
            return $exception;
        }

        $this->fail('Expected a challenge.');
    }

    public function testNoPageByDefault(): void
    {
        $this->assertSame([], $this->challenge($this->firewall())->getRenderContext()['page']);
    }

    /**
     * `challenge.page` reaches the page in `mode: exception`, and a host rendering its own
     * page finds it in the render context.
     */
    public function testAConfiguredPageReachesThePage(): void
    {
        $exception = $this->challenge($this->firewall(['page' => ['heading' => 'Un instant', 'lang' => 'fr']]));

        $this->assertSame(['lang' => 'fr', 'heading' => 'Un instant'], $exception->getRenderContext()['page']);

        $html = $exception->renderInterstitial(Request::create('/gated'));
        $this->assertStringContainsString('<html lang="fr">', $html);
        $this->assertStringContainsString('<h1>Un instant</h1>', $html);
    }

    /**
     * The fresh challenge that answers a refused submission is the same page.
     */
    public function testARefusedSubmissionCarriesThePage(): void
    {
        $exception = $this->challenge(
            $this->firewall(['page' => ['heading' => 'Un instant']]),
            Request::create('/_firewall/challenge', 'POST', ['answer' => 'wrong'], [], [], ['REMOTE_ADDR' => '203.0.113.9'])
        );

        $this->assertSame(['heading' => 'Un instant'], $exception->getRenderContext()['page']);
    }

    /**
     * An unusable page stops the firewall starting, so it is found at deploy rather than by
     * a visitor seeing the old page.
     */
    public function testAnUnusablePageIsAStartupError(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('challenge.page: styles must not contain "</style"');

        $this->firewall(['page' => ['styles' => '</style>']]);
    }

    /**
     * The linter reports each problem before deploy.
     */
    public function testTheLinterReportsAnUnusablePage(): void
    {
        $findings = (new ConfigLinter([[
            'challenge' => ['secret' => self::SECRET, 'page' => ['buton' => 'Go', 'lang' => '!!']],
            'plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'config' => ['path:/gated'],
            ]],
        ]]))->run();

        $titles = array_map(
            static fn(Diagnosis $diagnosis): string => $diagnosis->title,
            array_values(array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status === Diagnosis::ERROR))
        );

        $this->assertCount(2, $titles);
        $this->assertStringContainsString('unknown key "buton"', $titles[0]);
        $this->assertStringContainsString('lang must be a language tag', $titles[1]);
    }
}
