<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests the configurable source behind the `bot:` rule variable (#109).
 *
 * `bot:true` backed by device-detector alone misses roughly half the tooling a
 * firewall exists to stop. The wider crawler list catches it, and also counts
 * generic HTTP client libraries as bots — which would start blocking a partner
 * integration built on python-requests. So the source is configurable, the
 * default is the historical behaviour, and the gap is reported rather than
 * silently widened.
 */
class BotDetectorSourceTest extends AbstractTestCase
{
    /**
     * A scanner device-detector's bot database does not know.
     */
    private const SQLMAP = 'sqlmap/1.7.2#stable (https://sqlmap.org)';

    /**
     * A crawler it does know.
     */
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    /**
     * A real browser, which no source may match.
     */
    private const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

    /**
     * Captures what a plugin logs while it is constructed.
     */
    private TestHandler $handler;

    /**
     * {@inheritdoc}
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new TestHandler(Level::Debug);
        $logger = new Logger('bot-detector');
        $logger->pushHandler($this->handler);
        LoggingFactory::setLogger($logger);
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
     * Evaluate a rule under a given source.
     */
    private function ruleMatches(?string $source, string $rule, string $userAgent): bool
    {
        $metadata = $source === null ? [] : ['bot_detector' => $source];

        return (new UserAgent($metadata, [$rule]))->evaluate($this->request($userAgent));
    }

    /**
     * The default is unchanged, which is the whole point of shipping this now.
     */
    public function testDefaultSourceIsUnchanged(): void
    {
        $this->assertFalse(
            $this->ruleMatches(null, 'bot:true', self::SQLMAP),
            'The default must stay device-detector: widening it silently would change what an '
            . 'existing blocking rule matches.'
        );
        $this->assertTrue($this->ruleMatches(null, 'bot:true', self::GOOGLEBOT));
    }

    /**
     * Each source answers `bot:true` as documented.
     *
     * @param string $source
     *   The configured detector.
     * @param bool $catchesSqlmap
     *   Whether that source should match sqlmap.
     */
    #[DataProvider('sourceProvider')]
    public function testEachSourceAnswersBotAsDocumented(string $source, bool $catchesSqlmap): void
    {
        $this->assertSame($catchesSqlmap, $this->ruleMatches($source, 'bot:true', self::SQLMAP));

        // Every source still catches what the curated database knows, and none
        // of them touch a real browser.
        $this->assertTrue($this->ruleMatches($source, 'bot:true', self::GOOGLEBOT));
        $this->assertFalse($this->ruleMatches($source, 'bot:true', self::CHROME));
    }

    /**
     * The three sources and what each does with the gap.
     */
    public static function sourceProvider(): array
    {
        return [
            'device-detector' => ['device-detector', false],
            'crawler-detect' => ['crawler-detect', true],
            'both' => ['both', true],
        ];
    }

    /**
     * `automated:` is the union whatever the bot source is.
     *
     * Making it follow `bot_detector` would leave no way to ask the broad
     * question, which is the job that variable exists for.
     *
     * @param string $source
     *   The configured detector.
     */
    #[DataProvider('everySourceProvider')]
    public function testAutomatedIsAlwaysTheUnion(string $source): void
    {
        $this->assertTrue($this->ruleMatches($source, 'automated:true', self::SQLMAP));
        $this->assertTrue($this->ruleMatches($source, 'automated:true', self::GOOGLEBOT));
        $this->assertFalse($this->ruleMatches($source, 'automated:true', self::CHROME));
    }

    /**
     * Every configurable source.
     */
    public static function everySourceProvider(): array
    {
        return [
            'device-detector' => ['device-detector'],
            'crawler-detect' => ['crawler-detect'],
            'both' => ['both'],
        ];
    }

    /**
     * Client parsing survives a widened `bot:`.
     *
     * This is the constraint that makes the whole design work. Widening
     * `isBot()` itself would stop device-detector parsing the client, and
     * `client.name@contains:sqlmap` — the documented workaround for this very
     * gap, and a rule in the shipped example config — would break. Changing
     * what the *rule* resolves to leaves the parse decisions alone.
     *
     * @param string $source
     *   The configured detector.
     */
    #[DataProvider('everySourceProvider')]
    public function testClientParsingIsUnaffected(string $source): void
    {
        $this->assertTrue(
            $this->ruleMatches($source, 'client.name@contains:sqlmap', self::SQLMAP),
            'client.name must keep working under ' . $source
        );
    }

    /**
     * device-detector's richer bot metadata still wins where it has it.
     */
    public function testCuratedBotMetadataIsPreferred(): void
    {
        foreach (['device-detector', 'crawler-detect', 'both'] as $source) {
            $this->assertTrue(
                $this->ruleMatches($source, 'bot.name@contains:Googlebot', self::GOOGLEBOT),
                'bot.name should come from the curated database under ' . $source
            );
        }
    }

    /**
     * ...and the wider sources keep `bot.name` populated rather than empty.
     *
     * The crawler list carries only the substring it matched, but that is more
     * useful than dropping a documented field.
     */
    public function testWiderSourcesPopulateBotNameFromTheMatch(): void
    {
        $this->assertFalse($this->ruleMatches('device-detector', 'bot.name@contains:sqlmap', self::SQLMAP));
        $this->assertTrue($this->ruleMatches('crawler-detect', 'bot.name@contains:sqlmap', self::SQLMAP));
        $this->assertTrue($this->ruleMatches('both', 'bot.name@contains:sqlmap', self::SQLMAP));
    }

    /**
     * An unknown source falls back to the default and says so, rather than
     * quietly answering a different question than the operator asked.
     */
    public function testUnknownSourceFallsBackAndWarns(): void
    {
        $plugin = new UserAgent(['bot_detector' => 'magic'], ['bot:true']);

        $this->assertFalse($plugin->evaluate($this->request(self::SQLMAP)));
        $this->assertTrue($this->handler->hasRecordThatContains('Unknown bot_detector', Level::Warning));
    }

    /**
     * The coverage notice fires when `bot:` is used on its own.
     */
    public function testCoverageNoticeFiresForBotAlone(): void
    {
        new UserAgent([], ['bot:true']);

        $this->assertTrue(
            $this->handler->hasRecordThatContains('does not match sqlmap', Level::Notice),
            'An operator writing bot:true should be told what it misses.'
        );
    }

    /**
     * It stays quiet once the operator has engaged with the question.
     *
     * @param array<string, mixed> $metadata
     *   Plugin metadata.
     * @param array<int, mixed> $config
     *   Plugin rules.
     */
    #[DataProvider('quietProvider')]
    public function testCoverageNoticeStaysQuiet(array $metadata, array $config): void
    {
        new UserAgent($metadata, $config);

        $this->assertFalse($this->handler->hasRecordThatContains('does not match sqlmap', Level::Notice));
    }

    /**
     * Configurations that have already answered the question.
     */
    public static function quietProvider(): array
    {
        return [
            'automated alongside bot' => [[], ['bot:true', 'automated:true']],
            'automated only' => [[], ['automated:true']],
            'explicit default' => [['bot_detector' => 'device-detector'], ['bot:true']],
            'explicit wider source' => [['bot_detector' => 'both'], ['bot:true']],
            'no bot rule at all' => [[], ['client.name:Chrome']],
            'no rules' => [[], []],
        ];
    }

    /**
     * The notice looks inside groups, since a rule list is often nested.
     */
    public function testCoverageNoticeSeesNestedRules(): void
    {
        new UserAgent([], [
            ['type' => 'AND', 'rules' => ['bot:true', 'client.name:Chrome']],
        ]);

        $this->assertTrue($this->handler->hasRecordThatContains('does not match sqlmap', Level::Notice));
    }

    /**
     * ...including an `automated:` buried in a group, which counts as engaged.
     */
    public function testNestedAutomatedSilencesTheNotice(): void
    {
        new UserAgent([], [
            ['type' => 'OR', 'rules' => ['bot:true', 'automated:true']],
        ]);

        $this->assertFalse($this->handler->hasRecordThatContains('does not match sqlmap', Level::Notice));
    }
}
