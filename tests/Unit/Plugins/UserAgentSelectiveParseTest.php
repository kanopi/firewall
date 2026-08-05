<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use DeviceDetector\DeviceDetector;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\SelectiveDeviceDetector;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Parsing only as deep as the configured rules require (#108).
 *
 * The optimisation is invisible when it works and silent when it breaks — a
 * rule that stops matching because its phase was skipped looks exactly like a
 * rule that legitimately did not match. Most of these tests therefore compare
 * against a stock full parse rather than against hand-written expectations.
 */
final class UserAgentSelectiveParseTest extends AbstractTestCase
{
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
    private const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) '
        . 'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
    private const PIXEL = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 '
        . '(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    private const SQLMAP = 'sqlmap/1.8.3#stable (https://sqlmap.org)';
    private const GARBAGE = 'xyzzy-not-a-real-user-agent';

    /**
     * @param array<int, mixed> $config
     */
    private function plugin(array $config): UserAgent
    {
        // Caching off: this suite is about what gets parsed, and a shared
        // cache directory would couple these tests to #107's behaviour.
        return new class (['cache' => false], $config) extends UserAgent {
            public function phase(): string
            {
                return $this->requiredPhase();
            }
        };
    }

    private function request(string $userAgent): Request
    {
        return Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '1.1.1.1',
            'HTTP_USER_AGENT' => $userAgent,
        ]);
    }

    /**
     * Everything the plugin can read, for comparing two detectors.
     *
     * @return array<string, string>
     */
    private function snapshot(DeviceDetector $detector): array
    {
        return [
            'isBot' => var_export($detector->isBot(), true),
            'bot' => (string) json_encode($detector->getBot()),
            'device' => (string) $detector->getDeviceName(),
            'client' => (string) json_encode($detector->getClient()),
            'os' => (string) json_encode($detector->getOs()),
            'brand' => (string) $detector->getBrandName(),
            'model' => (string) $detector->getModel(),
        ];
    }

    // -----------------------------------------------------------------------
    // Equivalence with a stock parse
    // -----------------------------------------------------------------------

    /**
     * The property everything else rests on: at full depth, this must be
     * indistinguishable from `DeviceDetector::parse()`.
     */
    #[DataProvider('provideUserAgents')]
    public function testFullDepthMatchesStockParseExactly(string $userAgent): void
    {
        $stock = new DeviceDetector($userAgent);
        $stock->parse();

        $selective = new SelectiveDeviceDetector($userAgent);
        $selective->parseUpTo(SelectiveDeviceDetector::PHASE_DEVICE);

        $this->assertSame($this->snapshot($stock), $this->snapshot($selective));
    }

    /**
     * A shallower depth must agree with a full parse on every field it covers.
     * It may leave deeper fields empty; it must never report them differently.
     *
     * @param string $userAgent
     * @param string $depth
     * @param array<int, string> $covered
     */
    #[DataProvider('provideDepthCoverage')]
    public function testShallowDepthAgreesOnTheFieldsItCovers(
        string $userAgent,
        string $depth,
        array $covered,
    ): void {
        $stock = new DeviceDetector($userAgent);
        $stock->parse();
        $reference = $this->snapshot($stock);

        $selective = new SelectiveDeviceDetector($userAgent);
        $selective->parseUpTo($depth);
        $actual = $this->snapshot($selective);

        foreach ($covered as $field) {
            $this->assertSame(
                $reference[$field],
                $actual[$field],
                sprintf('Depth "%s" changed "%s" for %s', $depth, $field, $userAgent),
            );
        }
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function provideUserAgents(): array
    {
        return [
            'chrome desktop' => [self::CHROME],
            'iphone safari' => [self::IPHONE],
            'android pixel' => [self::PIXEL],
            'googlebot' => [self::GOOGLEBOT],
            'sqlmap' => [self::SQLMAP],
            'unrecognised' => [self::GARBAGE],
            'empty' => [''],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: array<int, string>}>
     */
    public static function provideDepthCoverage(): array
    {
        $cases = [];

        $depths = [
            SelectiveDeviceDetector::PHASE_BOT => ['isBot', 'bot'],
            SelectiveDeviceDetector::PHASE_OS => ['isBot', 'bot', 'os'],
            SelectiveDeviceDetector::PHASE_CLIENT => ['isBot', 'bot', 'os', 'client'],
        ];

        foreach (['chrome' => self::CHROME, 'iphone' => self::IPHONE, 'pixel' => self::PIXEL, 'googlebot' => self::GOOGLEBOT] as $name => $ua) {
            foreach ($depths as $depth => $covered) {
                $cases[$name . ' @ ' . $depth] = [$ua, $depth, $covered];
            }
        }

        return $cases;
    }

    /**
     * An unrecognised depth must parse everything rather than guess shallow.
     */
    public function testUnknownDepthParsesEverything(): void
    {
        $stock = new DeviceDetector(self::PIXEL);
        $stock->parse();

        $selective = new SelectiveDeviceDetector(self::PIXEL);
        $selective->parseUpTo('not-a-phase');

        $this->assertSame($this->snapshot($stock), $this->snapshot($selective));
    }

    /**
     * Bot detection runs at every depth. Skipping it would let a bot fall
     * through into client and device parsing it never reaches today.
     */
    public function testBotShortCircuitIsPreservedAtEveryDepth(): void
    {
        foreach (SelectiveDeviceDetector::PHASES as $depth) {
            $selective = new SelectiveDeviceDetector(self::GOOGLEBOT);
            $selective->parseUpTo($depth);

            $this->assertTrue($selective->isBot(), sprintf('Bot missed at depth "%s"', $depth));
            $this->assertEmpty(
                $selective->getClient(),
                sprintf('Depth "%s" parsed a client for a bot; stock parse does not.', $depth),
            );
        }
    }

    /**
     * `parse()` guards on `isParsed()`. Since the parent's flag is private,
     * the override has to keep that contract or a later `parse()` would redo
     * the work — and, worse, deepen a deliberately shallow parse.
     */
    public function testIsParsedContractSurvivesAndBlocksAReparse(): void
    {
        $selective = new SelectiveDeviceDetector(self::PIXEL);
        $this->assertFalse($selective->isParsed());

        $selective->parseUpTo(SelectiveDeviceDetector::PHASE_BOT);
        $this->assertTrue($selective->isParsed());

        // A later full parse must be a no-op, not a silent deepening.
        $selective->parse();
        $this->assertSame('', (string) $selective->getBrandName());
    }

    // -----------------------------------------------------------------------
    // Phase derivation from rules
    // -----------------------------------------------------------------------

    /**
     * @param array<int, mixed> $config
     */
    #[DataProvider('providePhaseDerivation')]
    public function testPhaseIsDerivedFromTheRules(array $config, string $expected): void
    {
        $this->assertSame($expected, $this->plugin($config)->phase());
    }

    /**
     * @return array<string, array{0: array<int, mixed>, 1: string}>
     */
    public static function providePhaseDerivation(): array
    {
        return [
            'bot only' => [['bot:true'], SelectiveDeviceDetector::PHASE_BOT],
            'bot with sub-key' => [['bot.name:Googlebot'], SelectiveDeviceDetector::PHASE_BOT],
            'os' => [['os.name:iOS'], SelectiveDeviceDetector::PHASE_OS],
            'client' => [['client.name@contains:sqlmap'], SelectiveDeviceDetector::PHASE_CLIENT],
            'device type' => [['device.type:desktop'], SelectiveDeviceDetector::PHASE_DEVICE],
            'brand' => [['brand:Apple'], SelectiveDeviceDetector::PHASE_DEVICE],
            'model' => [['model@contains:Pixel'], SelectiveDeviceDetector::PHASE_DEVICE],
            'deepest of several wins' => [
                ['bot:true', 'client.name:Chrome', 'os.name:iOS'],
                SelectiveDeviceDetector::PHASE_CLIENT,
            ],
            'negated rule' => [['!client.name:Chrome'], SelectiveDeviceDetector::PHASE_CLIENT],
            'comparison shorthand' => [['client.version > 80'], SelectiveDeviceDetector::PHASE_CLIENT],
            'array-match suffix' => [['client.name@in:a,b#any'], SelectiveDeviceDetector::PHASE_CLIENT],
            'structured rule' => [
                [['variable' => 'os.version', 'operator' => 'less_than', 'value' => '10']],
                SelectiveDeviceDetector::PHASE_OS,
            ],
            'nested AND group' => [
                [['type' => 'AND', 'rules' => ['bot:false', 'client.name:Chrome']]],
                SelectiveDeviceDetector::PHASE_CLIENT,
            ],
            'deeply nested group' => [
                [['type' => 'OR', 'rules' => [['type' => 'AND', 'rules' => ['bot:false', 'brand:Apple']]]]],
                SelectiveDeviceDetector::PHASE_DEVICE,
            ],
            // Fail-safe cases: anything unfamiliar costs performance, never
            // correctness.
            'unknown variable' => [['nonsense.field:x'], SelectiveDeviceDetector::PHASE_DEVICE],
            'malformed rule' => [['no-colon-here'], SelectiveDeviceDetector::PHASE_DEVICE],
            'non-string non-array rule' => [[42], SelectiveDeviceDetector::PHASE_DEVICE],
            'array without variable key' => [[['operator' => 'equals']], SelectiveDeviceDetector::PHASE_DEVICE],
            'empty config' => [[], SelectiveDeviceDetector::PHASE_BOT],
        ];
    }

    // -----------------------------------------------------------------------
    // End to end: the plugin's verdict is unchanged
    // -----------------------------------------------------------------------

    /**
     * The whole point. Whatever depth is chosen, the plugin must reach the
     * same verdict it would with a full parse.
     *
     * @param array<int, mixed> $config
     */
    #[DataProvider('provideVerdictCases')]
    public function testVerdictIsUnchangedBySelectiveParsing(
        array $config,
        string $userAgent,
        bool $expected,
    ): void {
        $this->assertSame(
            $expected,
            $this->plugin($config)->evaluate($this->request($userAgent)),
        );
    }

    /**
     * @return array<string, array{0: array<int, mixed>, 1: string, 2: bool}>
     */
    public static function provideVerdictCases(): array
    {
        return [
            'bot matches googlebot' => [['bot:true'], self::GOOGLEBOT, true],
            'bot does not match chrome' => [['bot:true'], self::CHROME, false],
            'bot name matches' => [['bot.name:Googlebot'], self::GOOGLEBOT, true],
            'client matches sqlmap' => [['client.name@contains:sqlmap'], self::SQLMAP, true],
            'client does not match chrome' => [['client.name@contains:sqlmap'], self::CHROME, false],
            'os matches iphone' => [['os.name:iOS'], self::IPHONE, true],
            'os does not match chrome' => [['os.name:iOS'], self::CHROME, false],
            'device type matches pixel' => [['device.type:smartphone'], self::PIXEL, true],
            'device type does not match desktop' => [['device.type:smartphone'], self::CHROME, false],
            'brand matches pixel' => [['brand:Google'], self::PIXEL, true],
            'model matches pixel' => [['model@contains:Pixel'], self::PIXEL, true],
            'grouped rule still matches' => [
                [['type' => 'AND', 'rules' => ['bot:false', 'os.name:Android']]],
                self::PIXEL,
                true,
            ],
        ];
    }

    /**
     * A device rule and a bot rule together must not let the bot rule's
     * shallow depth truncate the device one.
     */
    public function testMixedDepthConfigStillMatchesTheDeeperRule(): void
    {
        $plugin = $this->plugin(['bot:true', 'brand:Google']);

        $this->assertSame(SelectiveDeviceDetector::PHASE_DEVICE, $plugin->phase());
        $this->assertTrue($plugin->evaluate($this->request(self::PIXEL)));
    }

    /**
     * A second parseUpTo() is a no-op rather than a re-parse.
     *
     * Two plugins sharing one detector both ask it to parse, and device
     * detection is the expensive part of evaluating a request — re-running it
     * per plugin is the cost this class exists to avoid. The guard also has to
     * hold when the second call asks for a *deeper* phase, which is the case
     * that would otherwise quietly do the work twice.
     */
    public function testParseUpToIsIdempotent(): void
    {
        $selective = new SelectiveDeviceDetector(self::PIXEL);

        $selective->parseUpTo(SelectiveDeviceDetector::PHASE_BOT);
        $this->assertTrue($selective->isParsed());

        $selective->parseUpTo(SelectiveDeviceDetector::PHASE_DEVICE);

        $this->assertTrue($selective->isParsed(), 'A repeat call must not reset the parsed state.');
    }
}
