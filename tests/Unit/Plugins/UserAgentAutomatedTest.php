<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\SelectiveDeviceDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * The `automated:` rule variable (#109).
 *
 * `bot:true` is device-detector's curated bot database, and it misses sqlmap,
 * nikto, curl, python-requests and Go-http-client. `automated:true` is the
 * union of that database and a broader crawler list which catches them.
 *
 * A separate variable rather than a redefinition of `bot:`, because the wider
 * list counts generic HTTP client libraries as automated. Changing what
 * `bot:true` matches would start blocking traffic on a rule an operator wrote
 * long ago and has not touched.
 */
final class UserAgentAutomatedTest extends AbstractTestCase
{
    private const SQLMAP = 'sqlmap/1.8.3#stable (https://sqlmap.org)';
    private const NIKTO = 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)';
    private const CURL = 'curl/8.4.0';
    private const PYTHON = 'python-requests/2.31.0';
    private const GO = 'Go-http-client/1.1';
    private const MASSCAN = 'masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)';
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
    private const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) '
        . 'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';

    /**
     * @param array<int, mixed> $config
     */
    private function evaluate(array $config, string $userAgent): bool
    {
        // Caching off so this suite is not coupled to #107's cache directory.
        $plugin = new UserAgent(['cache' => false], $config);

        return $plugin->evaluate(Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '1.1.1.1',
            'HTTP_USER_AGENT' => $userAgent,
        ]));
    }

    // -----------------------------------------------------------------------
    // `bot:` must not move
    // -----------------------------------------------------------------------

    /**
     * Pins `bot:true` exactly as it behaves today. Anything that widens it
     * without the operator asking is a breaking change to a blocking rule,
     * and this is the test that should stop it.
     */
    #[DataProvider('provideBotBehaviour')]
    public function testBotVariableIsUnchanged(string $userAgent, bool $expected): void
    {
        $this->assertSame($expected, $this->evaluate(['bot:true'], $userAgent));
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function provideBotBehaviour(): array
    {
        return [
            // In device-detector's database.
            'masscan' => [self::MASSCAN, true],
            'googlebot' => [self::GOOGLEBOT, true],
            // The gap `automated:` exists to cover — still open for `bot:`.
            'sqlmap' => [self::SQLMAP, false],
            'nikto' => [self::NIKTO, false],
            'curl' => [self::CURL, false],
            'python-requests' => [self::PYTHON, false],
            'go-http-client' => [self::GO, false],
            // Never, under either variable.
            'chrome' => [self::CHROME, false],
            'iphone' => [self::IPHONE, false],
        ];
    }

    // -----------------------------------------------------------------------
    // `automated:` closes the gap
    // -----------------------------------------------------------------------

    #[DataProvider('provideToolingBotMisses')]
    public function testAutomatedCatchesWhatBotMisses(string $userAgent): void
    {
        $this->assertFalse(
            $this->evaluate(['bot:true'], $userAgent),
            'Precondition: bot:true should not catch this agent.',
        );
        $this->assertTrue(
            $this->evaluate(['automated:true'], $userAgent),
            'automated:true should catch it.',
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideToolingBotMisses(): array
    {
        return [
            'sqlmap' => [self::SQLMAP],
            'nikto' => [self::NIKTO],
            'curl' => [self::CURL],
            'python-requests' => [self::PYTHON],
            'go-http-client' => [self::GO],
        ];
    }

    /**
     * The union must not lose what device-detector already caught.
     */
    #[DataProvider('provideKnownBots')]
    public function testAutomatedKeepsWhatBotAlreadyCaught(string $userAgent): void
    {
        $this->assertTrue($this->evaluate(['automated:true'], $userAgent));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideKnownBots(): array
    {
        return ['masscan' => [self::MASSCAN], 'googlebot' => [self::GOOGLEBOT]];
    }

    /**
     * Wider coverage is only useful if it does not start blocking people.
     */
    #[DataProvider('provideBrowsers')]
    public function testBrowsersAreNeverAutomated(string $userAgent): void
    {
        $this->assertFalse($this->evaluate(['bot:true'], $userAgent));
        $this->assertFalse($this->evaluate(['automated:true'], $userAgent));
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideBrowsers(): array
    {
        return ['chrome' => [self::CHROME], 'iphone' => [self::IPHONE]];
    }

    public function testAutomatedFalseMatchesRealBrowsers(): void
    {
        $this->assertTrue($this->evaluate(['automated:false'], self::CHROME));
        $this->assertFalse($this->evaluate(['automated:false'], self::SQLMAP));
    }

    public function testEmptyUserAgentIsNotAutomated(): void
    {
        $this->assertFalse($this->evaluate(['automated:true'], ''));
    }

    // -----------------------------------------------------------------------
    // The regression that widening isBot() would have caused
    // -----------------------------------------------------------------------

    /**
     * The reason the crawler list is a separate signal rather than a wider
     * `isBot()`.
     *
     * Parsing stops as soon as `isBot()` is true, and `getClient()` returns
     * NULL once it has. Had the wider list fed `isBot()`, sqlmap would
     * short-circuit and `client.name@contains:sqlmap` would stop matching —
     * both the rule in the shipped example config and the documented
     * workaround for this very gap.
     */
    public function testClientRulesStillMatchForAgentsTheWiderListCatches(): void
    {
        $this->assertTrue($this->evaluate(['client.name@contains:sqlmap'], self::SQLMAP));

        // And still so when the same config also asks the wider question.
        $this->assertTrue(
            $this->evaluate(['automated:true', 'client.name@contains:sqlmap'], self::SQLMAP),
        );
    }

    /**
     * The detector's own bot flag drives the parse short-circuit, so it must
     * stay device-detector's alone.
     */
    public function testDetectorIsBotIsNotWidened(): void
    {
        $detector = new SelectiveDeviceDetector(self::SQLMAP);
        $detector->parseUpTo(SelectiveDeviceDetector::PHASE_CLIENT);

        $this->assertFalse($detector->isBot(), 'isBot() must remain device-detector only.');
        $this->assertTrue($detector->isCrawler(), 'The wider list should recognise sqlmap.');
        $this->assertNotEmpty($detector->getClient(), 'Client parsing must not have been short-circuited.');
    }

    public function testDetectorCrawlerCheckIgnoresAnEmptyAgent(): void
    {
        $detector = new SelectiveDeviceDetector('');
        $detector->parseUpTo(SelectiveDeviceDetector::PHASE_CLIENT);

        $this->assertFalse($detector->isCrawler());
    }

    // -----------------------------------------------------------------------
    // Sub-keys and composition
    // -----------------------------------------------------------------------

    /**
     * `bot.name` and friends come from the curated database. The wider list
     * yields a matched pattern rather than an identity, so an agent only it
     * recognises satisfies `automated:true` while exposing no name.
     */
    public function testBotSubKeysRemainDeviceDetectorOnly(): void
    {
        $this->assertTrue($this->evaluate(['bot.name:Googlebot'], self::GOOGLEBOT));
        $this->assertFalse($this->evaluate(['bot.name@contains:sqlmap'], self::SQLMAP));
    }

    /**
     * Being a normal rule variable, it composes with the rest of the syntax
     * rather than needing its own configuration section.
     */
    public function testAutomatedComposesWithGroupedRules(): void
    {
        $config = [[
            'type' => 'AND',
            'rules' => ['automated:true', 'client.name@contains:sqlmap'],
        ]];

        $this->assertTrue($this->evaluate($config, self::SQLMAP));
        // Googlebot is automated but is not sqlmap, so the AND fails.
        $this->assertFalse($this->evaluate($config, self::GOOGLEBOT));
    }

    public function testAutomatedComposesWithNegation(): void
    {
        $this->assertTrue($this->evaluate(['!automated:true'], self::CHROME));
        $this->assertFalse($this->evaluate(['!automated:true'], self::SQLMAP));
    }

    /**
     * The wider list reads the raw user agent, so it needs no parse beyond the
     * bot phase — an `automated:`-only config stays as cheap as a `bot:`-only
     * one (#108).
     */
    public function testAutomatedDoesNotDeepenTheParse(): void
    {
        $plugin = new class (['cache' => false], ['automated:true']) extends UserAgent {
            public function phase(): string
            {
                return $this->requiredPhase();
            }
        };

        $this->assertSame(SelectiveDeviceDetector::PHASE_BOT, $plugin->phase());
    }
}
