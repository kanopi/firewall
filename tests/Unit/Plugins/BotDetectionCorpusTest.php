<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Pins what `bot:true` and `automated:true` actually catch (#165).
 *
 * Two jobs. It turns "does automated catch X" from a question into a test, and
 * it catches an upstream regression when either detection library is bumped —
 * both are third-party curated lists that change without asking us.
 *
 * The table in `docs/plugins/user-agent.md` is what people read to decide which
 * variable to write, so it has to stay true. This file is the executable
 * version of it.
 */
class BotDetectionCorpusTest extends AbstractTestCase
{
    /**
     * Evaluate one rule against a user agent.
     */
    private function matchesRule(string $rule, string $userAgent): bool
    {
        return (new UserAgent([], [$rule]))->evaluate(
            Request::create('/', 'GET', [], [], [], [
                'REMOTE_ADDR' => '203.0.113.9',
                'HTTP_USER_AGENT' => $userAgent,
            ])
        );
    }

    /**
     * Agents both variables catch: crawlers the bot database knows.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('caughtByBothProvider')]
    public function testCaughtByBotAndAutomated(string $userAgent): void
    {
        $this->assertTrue($this->matchesRule('bot:true', $userAgent), 'bot:true — ' . $userAgent);
        $this->assertTrue($this->matchesRule('automated:true', $userAgent), 'automated:true — ' . $userAgent);
    }

    /**
     * Crawlers and scanners the curated bot database classifies.
     */
    public static function caughtByBothProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            // Search and SEO crawlers
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
            'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)',
            // Scanners the bot database does know — the second row of the
            // table in docs/plugins/user-agent.md.
            'masscan/1.3',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
            'Mozilla/5.0 zgrab/0.x',
            'WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)',
            'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
            'DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)',
            // Reported as slipping through, and verified here that they do not
            'Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'Mozilla/5.0 (compatible; ReflectionBot/1.0)',
            'MathPicDatasetCrawler/1.0',
            'meta-webindexer/1.0',
            'Mozilla/5.0 (compatible; ShapBot/1.0)',
            'Mozilla/5.0 (compatible; AionBot/1.0)',
        ]);
    }

    /**
     * Agents only `automated:true` catches.
     *
     * This is the distinction the two variables exist for, and the reason a
     * config using `bot:true` can look like weak detection: generic HTTP client
     * libraries and some scanners are not in the curated bot database.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('caughtOnlyByAutomatedProvider')]
    public function testCaughtOnlyByAutomated(string $userAgent): void
    {
        $this->assertFalse($this->matchesRule('bot:true', $userAgent), 'bot:true — ' . $userAgent);
        $this->assertTrue($this->matchesRule('automated:true', $userAgent), 'automated:true — ' . $userAgent);
    }

    /**
     * Tooling and client libraries outside the curated bot database.
     */
    public static function caughtOnlyByAutomatedProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            'sqlmap/1.7.2#stable (https://sqlmap.org)',
            'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)',
            'curl/8.4.0',
            'python-requests/2.31.0',
            'Go-http-client/1.1',
            'python-httpx/0.27.0',
        ]);
    }

    /**
     * Real browsers are neither.
     *
     * The negative control. A detection change that started catching these
     * would be far worse than one that missed a crawler.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('humanProvider')]
    public function testRealBrowsersAreNeitherBotNorAutomated(string $userAgent): void
    {
        $this->assertFalse($this->matchesRule('bot:true', $userAgent), 'bot:true — ' . $userAgent);
        $this->assertFalse($this->matchesRule('automated:true', $userAgent), 'automated:true — ' . $userAgent);
    }

    /**
     * Browsers that must never be classified as automated.
     */
    public static function humanProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0',
        ]);
    }

    /**
     * Detection reads a substring, so a bare token in a log line is caught too.
     */
    public function testBareTokensAreCaught(): void
    {
        foreach (['petalbot', 'baiduspider', 'python-httpx', 'Go-http-client'] as $token) {
            $this->assertTrue(
                $this->matchesRule('automated:true', $token),
                'automated:true should catch the bare token ' . $token
            );
        }
    }
}
