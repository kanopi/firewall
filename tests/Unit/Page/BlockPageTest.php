<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Page;

use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Page\BlockPage;
use Kanopi\Firewall\Page\PageRenderer;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * The page a refused visitor sees: `global.block_page` and `global.lockdown_page` (#452).
 *
 * A block was one line of `text/plain`, and the docs suggested loading an HTML file into
 * `banning_message`, which a browser then showed as source.
 */
final class BlockPageTest extends AbstractTestCase
{
    /**
     * @param array<string, mixed> $global
     * @param array<string, mixed> $metadata
     *   The blocking rule's metadata.
     */
    private function firewall(array $global = [], array $metadata = []): Firewall
    {
        return Firewall::create([[
            'global' => $global + ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => Url::class,
                'response' => 'block',
                'enable' => true,
                'metadata' => $metadata + ['name' => 'no-admin', 'status_code' => 403],
                'config' => ['path:/admin'],
            ]],
        ]]);
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(string $path = '/admin', array $headers = []): Request
    {
        $request = Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);
        $request->headers->add($headers);

        return $request;
    }

    private function blocked(Firewall $firewall, ?Request $request = null): FirewallBlockedException
    {
        try {
            $firewall->evaluate($request ?? $this->request());
        } catch (FirewallBlockedException $exception) {
            return $exception;
        }

        $this->fail('Expected a block.');
    }

    // -----------------------------------------------------------------------
    // Unchanged unless asked for
    // -----------------------------------------------------------------------

    /**
     * No page configured: the plain-text message a block has always been.
     */
    public function testWithoutAPageABlockIsThePlainTextItWas(): void
    {
        $exception = $this->blocked($this->firewall());

        $this->assertSame('text/plain; charset=utf-8', $exception->getContentType());
        $this->assertMatchesRegularExpression('/^[0-9A-F]{32} Request Banned$/', $exception->getMessage());
        $this->assertSame(403, $exception->getStatusCode());
    }

    public function testFalseIsNoPage(): void
    {
        $this->assertSame('text/plain; charset=utf-8', $this->blocked($this->firewall(['block_page' => false]))->getContentType());
    }

    // -----------------------------------------------------------------------
    // The page
    // -----------------------------------------------------------------------

    /**
     * `block_page: true` is the built-in page, quoting the reference a visitor can send.
     */
    public function testTrueIsTheBuiltInPage(): void
    {
        $exception = $this->blocked($this->firewall(['block_page' => true]));
        $html = $exception->getMessage();
        $id = $this->requestId($html);

        $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
        $this->assertSame(403, $exception->getStatusCode());
        $this->assertStringStartsWith('<!DOCTYPE html>', $html);
        $this->assertStringContainsString('<html lang="en">', $html);
        $this->assertStringContainsString('<title>Request blocked</title>', $html);
        $this->assertStringContainsString('<h1>Request blocked</h1>', $html);
        $this->assertStringContainsString("<p>This request was blocked by the site&#039;s firewall.</p>", $html);
        $this->assertStringContainsString('quote reference ' . $id . '.</p>', $html);
        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringNotContainsString('<form', $html);
    }

    /**
     * The card, heading and base rules are the challenge interstitial's, so one set of
     * `styles` themes both.
     */
    public function testItSharesTheInterstitialsLook(): void
    {
        $block = $this->blocked($this->firewall(['block_page' => true]))->getMessage();
        $challenge = (new MathChallengeProvider(new TokenManager('s')))->renderInterstitial(Request::create('/'), [
            'submit_url' => '/_firewall/challenge',
            'redirect_to' => '/',
            'ttl' => '60',
            'header_name' => '',
        ]);

        foreach ([$block, $challenge] as $html) {
            $this->assertStringContainsString(PageRenderer::BASE_STYLES, $html);
            $this->assertStringContainsString('<main class="card">', $html);
        }
    }

    /**
     * Every key, and a multi-line message as one paragraph per line.
     */
    public function testEveryKeyIsApplied(): void
    {
        $html = $this->blocked($this->firewall(['block_page' => [
            'lang' => 'fr',
            'title' => 'Accès refusé',
            'heading' => 'Accès refusé',
            'message' => "Cette requête a été bloquée.\n\nRéférence : {{request.id}}",
            'styles' => '.card { border-top: 4px solid #b00; }',
            'stylesheet' => 'https://cdn.example.com/firewall.css',
        ]]))->getMessage();
        $id = $this->requestId($html);

        $this->assertStringContainsString('<html lang="fr">', $html);
        $this->assertStringContainsString('<title>Accès refusé</title>', $html);
        $this->assertStringContainsString('<h1>Accès refusé</h1>', $html);
        $this->assertStringContainsString("<p>Cette requête a été bloquée.</p>\n    <p>Référence : " . $id . '</p>', $html);
        $this->assertStringContainsString('.card { border-top: 4px solid #b00; }', $html);
        $this->assertStringContainsString('<link rel="stylesheet" href="https://cdn.example.com/firewall.css">', $html);
        $this->assertStringNotContainsString('Request blocked', $html);
    }

    /**
     * A page with no message of its own shows `banning_message`.
     */
    public function testThePageFallsBackToTheBanningMessage(): void
    {
        $html = $this->blocked($this->firewall([
            'block_page' => ['heading' => 'Stop'],
            'banning_message' => 'Refused with status {{block.status}}.',
        ]))->getMessage();

        $this->assertStringContainsString('<p>Refused with status 403.</p>', $html);
    }

    /**
     * What the client sent is substituted and escaped exactly once: never markup, and
     * never `&amp;lt;` on the visitor's screen.
     */
    public function testSubstitutionsAreEscapedOnce(): void
    {
        $html = $this->blocked(
            $this->firewall(['block_page' => ['message' => 'You sent {{request.header.X-Probe}}']]),
            $this->request('/admin', ['X-Probe' => '<script>alert(1)</script> & co'])
        )->getMessage();

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('<p>You sent &lt;script&gt;alert(1)&lt;/script&gt; &amp; co</p>', $html);
        $this->assertStringNotContainsString('&amp;lt;', $html);
    }

    /**
     * The operator's own text is plain text too.
     */
    public function testTheOperatorsTextIsEscaped(): void
    {
        $html = $this->blocked($this->firewall(['block_page' => [
            'title' => '<b>t</b>',
            'heading' => '<i>h</i>',
            'message' => '<img src=x onerror=alert(1)>',
        ]]))->getMessage();

        $this->assertStringNotContainsString('<b>t</b>', $html);
        $this->assertStringNotContainsString('<i>h</i>', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringContainsString('&lt;img src=x onerror=alert(1)&gt;', $html);
    }

    // -----------------------------------------------------------------------
    // Per rule
    // -----------------------------------------------------------------------

    /**
     * A rule's page is merged over the global one.
     */
    public function testARulesPageIsMergedOverTheGlobalOne(): void
    {
        $html = $this->blocked($this->firewall(
            ['block_page' => ['lang' => 'de', 'heading' => 'Global']],
            ['block_page' => ['heading' => 'Rule', 'message' => 'Not this path.']]
        ))->getMessage();

        $this->assertStringContainsString('<html lang="de">', $html);
        $this->assertStringContainsString('<h1>Rule</h1>', $html);
        $this->assertStringContainsString('<p>Not this path.</p>', $html);
    }

    /**
     * A rule can have a page when nothing global does.
     */
    public function testARuleCanHaveAPageOfItsOwn(): void
    {
        $exception = $this->blocked($this->firewall([], ['block_page' => true]));

        $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
    }

    /**
     * A rule's own plain-text message, with the placeholders a block adds.
     */
    public function testARulesMessageReplacesTheGlobalOne(): void
    {
        $exception = $this->blocked($this->firewall(
            ['banning_message' => 'global'],
            ['banning_message' => '{{block.rule}} refused this with {{block.status}}']
        ));

        $this->assertSame('text/plain; charset=utf-8', $exception->getContentType());
        $this->assertSame('no-admin refused this with 403', $exception->getMessage());
    }

    /**
     * The rule's name is never in a default: it tells the client which rule refused it.
     */
    public function testNoDefaultNamesTheRule(): void
    {
        $this->assertStringNotContainsString('no-admin', $this->blocked($this->firewall())->getMessage());
        $this->assertStringNotContainsString('no-admin', $this->blocked($this->firewall(['block_page' => true]))->getMessage());
    }

    // -----------------------------------------------------------------------
    // JSON
    // -----------------------------------------------------------------------

    /**
     * With `banning_json`, a client whose first preference is JSON gets JSON.
     */
    public function testAJsonClientGetsJson(): void
    {
        $exception = $this->blocked(
            $this->firewall(['banning_json' => true, 'block_page' => true]),
            $this->request('/admin', ['Accept' => 'application/json'])
        );

        $this->assertSame('application/json; charset=utf-8', $exception->getContentType());
        $body = json_decode($exception->getMessage(), true);
        $this->assertIsArray($body);
        $this->assertSame('blocked', $body['error']);
        $this->assertSame(403, $body['status']);
        $this->assertMatchesRegularExpression('/^[0-9A-F]{32}$/', $body['request_id']);
    }

    /**
     * A browser accepts anything after HTML, and still gets the page.
     */
    public function testABrowserStillGetsThePage(): void
    {
        $exception = $this->blocked(
            $this->firewall(['banning_json' => true, 'block_page' => true]),
            $this->request('/admin', ['Accept' => 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'])
        );

        $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
    }

    /**
     * Without `banning_json`, Accept changes nothing.
     */
    public function testJsonIsOptIn(): void
    {
        $exception = $this->blocked($this->firewall(), $this->request('/admin', ['Accept' => 'application/json']));

        $this->assertSame('text/plain; charset=utf-8', $exception->getContentType());
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function accepts(): array
    {
        return [
            'json' => ['application/json', true],
            'a +json type' => ['application/problem+json', true],
            'json first' => ['application/json, text/html;q=0.5', true],
            'html first' => ['text/html, application/json;q=0.9', false],
            'anything' => ['*/*', false],
            'nothing said' => ['', false],
        ];
    }

    #[DataProvider('accepts')]
    public function testPrefersJson(string $accept, bool $expected): void
    {
        $request = Request::create('/');
        $request->headers->set('Accept', $accept);

        $this->assertSame($expected, BlockPage::prefersJson($request));
    }

    // -----------------------------------------------------------------------
    // Lockdown
    // -----------------------------------------------------------------------

    /**
     * @param array<string, mixed> $global
     */
    private function lockedDown(array $global = [], ?Request $request = null): FirewallLockdownException
    {
        try {
            $this->firewall($global + ['lockdown' => true, 'lockdown_allow' => ['198.51.100.0/24']])
                ->evaluate($request ?? $this->request('/'));
        } catch (FirewallLockdownException $exception) {
            return $exception;
        }

        $this->fail('Expected a lockdown.');
    }

    public function testWithoutAPageALockdownIsThePlainTextItWas(): void
    {
        $exception = $this->lockedDown();

        $this->assertSame('text/plain; charset=utf-8', $exception->getContentType());
        $this->assertSame('This site is temporarily closed to visitors. Please try again shortly.', $exception->getMessage());
    }

    public function testALockdownPage(): void
    {
        $exception = $this->lockedDown(['lockdown_page' => ['heading' => 'Back soon'], 'lockdown_message' => 'Upgrading until 18:00 UTC.']);
        $html = $exception->getMessage();

        $this->assertSame('text/html; charset=utf-8', $exception->getContentType());
        $this->assertSame(503, $exception->getStatusCode());
        $this->assertStringContainsString('<title>Temporarily closed</title>', $html);
        $this->assertStringContainsString('<h1>Back soon</h1>', $html);
        $this->assertStringContainsString('<p>Upgrading until 18:00 UTC.</p>', $html);
    }

    /**
     * The block page is the block page: a lockdown does not borrow it.
     */
    public function testALockdownDoesNotUseTheBlockPage(): void
    {
        $this->assertSame('text/plain; charset=utf-8', $this->lockedDown(['block_page' => true])->getContentType());
    }

    public function testALockdownAnswersJsonWithRetryAfter(): void
    {
        $exception = $this->lockedDown(
            ['banning_json' => true, 'lockdown_retry_after' => 120],
            $this->request('/', ['Accept' => 'application/json'])
        );

        $this->assertSame(
            ['error' => 'lockdown', 'status' => 503, 'request_id' => json_decode($exception->getMessage(), true)['request_id'] ?? null, 'retry_after' => 120],
            json_decode($exception->getMessage(), true)
        );
        $this->assertSame(120, $exception->getRetryAfter());
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{array<string, mixed>, array<string, mixed>, string}>
     */
    public static function unusable(): array
    {
        return [
            'a page that is text' => [['block_page' => 'yes'], [], 'global.block_page: must be true, false or a map'],
            'an unknown key' => [['block_page' => ['button' => 'Go']], [], 'global.block_page: unknown key "button"'],
            'css closing its block' => [['block_page' => ['styles' => '</style><script>']], [], 'must not contain "</style"'],
            'a lockdown page with a bad lang' => [['lockdown_page' => ['lang' => 'not a tag']], [], 'global.lockdown_page: lang must be'],
            'a rule page' => [[], ['block_page' => ['stylesheet' => 'javascript:x']], 'rule "no-admin" metadata.block_page: stylesheet must be'],
            'a rule message that is not text' => [[], ['banning_message' => ['x']], 'rule "no-admin" metadata.banning_message must be text'],
        ];
    }

    /**
     * @param array<string, mixed> $global
     * @param array<string, mixed> $metadata
     */
    #[DataProvider('unusable')]
    public function testAnUnusableSettingIsAStartupError(array $global, array $metadata, string $expected): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage($expected);

        $this->firewall($global, $metadata);
    }

    public function testTheLinterReportsAnUnusablePage(): void
    {
        $findings = (new ConfigLinter([[
            'global' => ['block_page' => ['button' => 'Go'], 'lockdown_page' => 7],
            'plugins' => [[
                'plugin' => Url::class,
                'response' => 'block',
                'metadata' => ['name' => 'r', 'block_page' => ['lang' => '!!']],
                'config' => ['path:/admin'],
            ]],
        ]]))->run();

        $titles = array_map(
            static fn(Diagnosis $diagnosis): string => $diagnosis->title,
            array_values(array_filter($findings, static fn(Diagnosis $diagnosis): bool => $diagnosis->status === Diagnosis::ERROR))
        );

        $this->assertCount(3, $titles);
        $this->assertStringContainsString('`global.block_page`', $titles[0]);
        $this->assertStringContainsString('unknown key "button"', $titles[0]);
        $this->assertStringContainsString('`global.lockdown_page`', $titles[1]);
        $this->assertStringContainsString('rule "r"', $titles[2]);
    }

    /**
     * The request ID the firewall put on the page.
     */
    private function requestId(string $html): string
    {
        $this->assertSame(1, preg_match('/[0-9A-F]{32}/', $html, $match));

        return $match[0];
    }
}
