<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Presets;

use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the AI crawler presets against real user-agent strings.
 *
 * Two things are worth guarding. That the presets actually load their list from
 * the file beside them — the path resolution for that is new — and that the two
 * lists stay separate, because blocking an answer engine has a traffic cost
 * that blocking a training crawler does not.
 */
class AiCrawlerPresetTest extends AbstractTestCase
{
    /**
     * Build the Url plugin from a shipped preset.
     */
    private function plugin(string $preset): Url
    {
        $config = Config::loadFile(dirname(__DIR__, 3) . '/presets/' . $preset);

        $this->assertSame([], Config::getLoadErrors(), 'The preset itself must load cleanly.');

        return new Url(
            $config['plugins'][0]['metadata'] ?? [],
            $config['plugins'][0]['config'] ?? []
        );
    }

    /**
     * A request carrying a user agent.
     */
    private function request(string $userAgent): Request
    {
        return Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => $userAgent,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();
        Config::clearLoadErrors();
    }

    /**
     * The preset reads its list from the file shipped beside it.
     *
     * A relative `upstream` used to stay relative and be read against the
     * process working directory, which for a web request is wherever the front
     * controller happens to live.
     */
    public function testPresetLoadsItsListFromDisk(): void
    {
        $plugin = $this->plugin('ai-crawlers.yml');

        $reflection = new \ReflectionProperty(Url::class, 'config');
        $reflection->setAccessible(true);
        $rules = $reflection->getValue($plugin);

        $this->assertNotEmpty($rules, 'The source produced no rules — the list was not found.');
        $this->assertContains('header.user-agent@contains:GPTBot', $rules);
        $this->assertContains('header.user-agent@contains:CCBot', $rules);
    }

    /**
     * Training crawlers are blocked by the training preset.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('trainingCrawlerProvider')]
    public function testTrainingCrawlersAreBlocked(string $userAgent): void
    {
        $this->assertTrue(
            $this->plugin('ai-crawlers.yml')->evaluate($this->request($userAgent)),
            $userAgent
        );
    }

    /**
     * User agents the training list should catch.
     */
    public static function trainingCrawlerProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot',
            'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
            'CCBot/2.0 (https://commoncrawl.org/faq/)',
            'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)',
            'Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)',
            'Mozilla/5.0 (compatible; Google-Extended/1.0)',
            'meta-externalagent/1.1',
            'Diffbot/0.1',
        ]);
    }

    /**
     * Answer engines are NOT blocked by the training preset.
     *
     * This is the separation the two lists exist for. A site blocking training
     * crawlers has usually not decided to give up answer-engine referrals, and
     * finding out it did by accident is the worst way to learn.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('answerEngineProvider')]
    public function testAnswerEnginesAreNotBlockedByTheTrainingPreset(string $userAgent): void
    {
        $this->assertFalse(
            $this->plugin('ai-crawlers.yml')->evaluate($this->request($userAgent)),
            $userAgent
        );
    }

    /**
     * Answer engines are blocked by their own preset.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('answerEngineProvider')]
    public function testAnswerEnginesAreBlockedByTheirOwnPreset(string $userAgent): void
    {
        $this->assertTrue(
            $this->plugin('ai-answer-engines.yml')->evaluate($this->request($userAgent)),
            $userAgent
        );
    }

    /**
     * User agents that fetch on demand and cite the result.
     */
    public static function answerEngineProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)',
            'Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)',
            'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)',
            'Mozilla/5.0 (compatible; YouBot/1.0)',
            'Mozilla/5.0 (compatible; DuckAssistBot/1.0)',
        ]);
    }

    /**
     * Neither preset touches search engines or real browsers.
     *
     * Google-Extended and Googlebot are different crawlers, and blocking the
     * wrong one deindexes the site. Applebot-Extended and Applebot likewise.
     *
     * @param string $userAgent
     *   A realistic user-agent string.
     */
    #[DataProvider('mustNotBlockProvider')]
    public function testNeitherPresetBlocksSearchOrBrowsers(string $userAgent): void
    {
        $this->assertFalse(
            $this->plugin('ai-crawlers.yml')->evaluate($this->request($userAgent)),
            'ai-crawlers.yml blocked: ' . $userAgent
        );

        Config::clearLoadErrors();

        $this->assertFalse(
            $this->plugin('ai-answer-engines.yml')->evaluate($this->request($userAgent)),
            'ai-answer-engines.yml blocked: ' . $userAgent
        );
    }

    /**
     * Traffic that must keep flowing.
     */
    public static function mustNotBlockProvider(): array
    {
        return array_map(static fn (string $agent): array => [$agent], [
            // Search indexing. Google-Extended is on the training list;
            // Googlebot must never be.
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)',
            // Applebot powers Siri and Spotlight; Applebot-Extended is training.
            'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)',
            // Real browsers.
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
            // Monitoring.
            'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)',
        ]);
    }

    /**
     * The challenge preset carries the same rules, with a different response.
     */
    public function testChallengePresetMirrorsTheBlockPreset(): void
    {
        $block = Config::loadFile(dirname(__DIR__, 3) . '/presets/ai-crawlers.yml');
        Config::clearLoadErrors();
        $challenge = Config::loadFile(dirname(__DIR__, 3) . '/presets/ai-crawlers-challenge.yml');

        $this->assertSame('block', $block['plugins'][0]['response']);
        $this->assertSame('challenge', $challenge['plugins'][0]['response']);
        $this->assertSame(
            $block['plugins'][0]['metadata']['sources'][0]['upstream'],
            $challenge['plugins'][0]['metadata']['sources'][0]['upstream'],
            'Both presets must read the same list.'
        );
    }

    /**
     * Matching is case-insensitive, since crawlers vary their own casing.
     */
    public function testMatchingIsCaseInsensitive(): void
    {
        $plugin = $this->plugin('ai-crawlers.yml');

        $this->assertTrue($plugin->evaluate($this->request('gptbot/1.2')));
        $this->assertTrue($plugin->evaluate($this->request('CLAUDEBOT/1.0')));
    }
}
