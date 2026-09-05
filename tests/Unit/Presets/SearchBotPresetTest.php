<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Presets;

use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the search engine crawler allow preset.
 *
 * The scoping is the whole point of this file. `response: allow` short-circuits
 * evaluation, and a user-agent string is trivially forged, so an unscoped
 * version of this preset would be a firewall bypass anyone could use with one
 * curl flag. Every test below is really asking the same question: does the
 * bypass stop at the front door.
 */
class SearchBotPresetTest extends AbstractTestCase
{
    /**
     * Build the Url plugin from the preset.
     */
    private function plugin(): Url
    {
        $config = Config::loadFile(dirname(__DIR__, 3) . '/presets/search-bots.yml');

        $this->assertSame([], Config::getLoadErrors(), 'The preset itself must load cleanly.');

        return new Url(
            $config['plugins'][0]['metadata'] ?? [],
            $config['plugins'][0]['config'] ?? []
        );
    }

    /**
     * A request for a path with a user agent.
     */
    private function request(string $path, string $userAgent): Request
    {
        return Request::create($path, 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => $userAgent,
        ]);
    }

    /**
     * A realistic Googlebot user agent.
     */
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        Config::clearLoadErrors();
    }

    /**
     * The preset is an allow rule, which is what makes the scoping matter.
     */
    public function testPresetIsAnAllowRuleAtNegativeWeight(): void
    {
        $config = Config::loadFile(dirname(__DIR__, 3) . '/presets/search-bots.yml');

        $this->assertSame('allow', $config['plugins'][0]['response']);
        $this->assertLessThan(
            -100,
            $config['plugins'][0]['weight'],
            'An allow must run ahead of the block and challenge entries it exists to pre-empt.'
        );
    }

    /**
     * Search crawlers are allowed through for public content.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('searchCrawlerProvider')]
    public function testSearchCrawlersAreAllowedOnPublicContent(string $userAgent): void
    {
        $this->assertTrue(
            $this->plugin()->evaluate($this->request('/blog/a-post', $userAgent)),
            $userAgent
        );
    }

    /**
     * The crawlers whose indexing a site presumably wants.
     */
    public static function searchCrawlerProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            self::GOOGLEBOT,
            'Googlebot-Image/1.0',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)',
            'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        ]);
    }

    /**
     * The bypass stops at the administrative surface.
     *
     * This is the test that matters. A forged Googlebot header gets a pass on
     * public pages and meets the firewall exactly where it would do damage.
     *
     * @param string $path
     *   A path that must not be covered by the allow.
     */
    #[DataProvider('protectedPathProvider')]
    public function testTheAllowDoesNotCoverTheAdminSurface(string $path): void
    {
        $this->assertFalse(
            $this->plugin()->evaluate($this->request($path, self::GOOGLEBOT)),
            sprintf('A forged crawler must not be allowed past %s', $path)
        );
    }

    /**
     * Paths a crawler has no business asking for.
     */
    public static function protectedPathProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            // WordPress
            '/wp-admin',
            '/wp-admin/',
            '/wp-admin/admin-ajax.php',
            '/wp-login.php',
            '/wp-json/wp/v2/users',
            '/xmlrpc.php',
            // Drupal
            '/admin',
            '/admin/content',
            '/user/login',
            '/user/register',
            '/user/password',
            '/user/reset/1/2/3',
            '/node/add',
            '/node/add/article',
        ]);
    }

    /**
     * Public paths that merely resemble the protected ones stay allowed.
     *
     * The prefixes are anchored for this reason: a site with a page at
     * /administrative-services or a public profile at /user/42 should not lose
     * crawler access to it.
     *
     * @param string $path
     *   A public path.
     */
    #[DataProvider('lookalikePathProvider')]
    public function testLookalikePublicPathsStayAllowed(string $path): void
    {
        $this->assertTrue(
            $this->plugin()->evaluate($this->request($path, self::GOOGLEBOT)),
            sprintf('%s is public and should still be crawlable', $path)
        );
    }

    /**
     * Public paths that share a prefix with a protected one.
     */
    public static function lookalikePathProvider(): array
    {
        return array_map(static fn (string $path): array => [$path], [
            '/administrative-services',
            '/administration-team',
            '/user/42',
            '/users',
            '/news/admin-appointed-to-board',
            '/wp-content/uploads/2026/09/photo.jpg',
            '/adminium',
        ]);
    }

    /**
     * Everything else gets no allow at all, which is the default posture.
     *
     * @param string $userAgent
     *   A user agent that is not a search crawler.
     */
    #[DataProvider('nonCrawlerProvider')]
    public function testNonCrawlersAreNotAllowed(string $userAgent): void
    {
        $this->assertFalse(
            $this->plugin()->evaluate($this->request('/', $userAgent)),
            $userAgent
        );
    }

    /**
     * Agents the preset must not vouch for.
     */
    public static function nonCrawlerProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36',
            'sqlmap/1.7.2#stable (https://sqlmap.org)',
            'curl/8.4.0',
            'python-requests/2.31.0',
            // Training crawlers are a different decision and must not be
            // allowed by the preset that keeps search working.
            'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)',
            'Mozilla/5.0 (compatible; Google-Extended/1.0)',
            'Mozilla/5.0 (compatible; Applebot-Extended/1.0)',
            'Mozilla/5.0 (compatible; ClaudeBot/1.0)',
            // SEO tooling is deliberately out of the list.
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
            'Mozilla/5.0 (compatible; SemrushBot/7~bl)',
        ]);
    }

    /**
     * Google-Extended must not be allowed by a rule matching "Googlebot".
     *
     * Substring matching makes this worth pinning: the two names are close,
     * they mean opposite things, and getting it wrong either deindexes the site
     * or hands training collection a pass.
     */
    public function testGoogleExtendedIsNotCoveredByGooglebot(): void
    {
        $plugin = $this->plugin();

        $this->assertTrue($plugin->evaluate($this->request('/', self::GOOGLEBOT)));
        $this->assertFalse(
            $plugin->evaluate($this->request('/', 'Mozilla/5.0 (compatible; Google-Extended/1.0)'))
        );
    }

    /**
     * The preset reads its list from the file shipped beside it.
     */
    public function testPresetLoadsItsListFromDisk(): void
    {
        $reflection = new \ReflectionProperty(Url::class, 'config');
        $reflection->setAccessible(true);
        $rules = $reflection->getValue($this->plugin());

        $this->assertNotEmpty($rules, 'The source produced no rules — the list was not found.');
        $this->assertIsArray($rules[0], 'Each rule should be the scoped AND group, not a bare string.');
        $this->assertSame('AND', $rules[0]['type']);
        $this->assertCount(3, $rules[0]['rules'], 'Dropping a scope rule would widen the bypass.');
    }
}
