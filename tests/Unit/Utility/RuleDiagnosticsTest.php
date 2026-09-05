<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\Asn;
use Kanopi\Firewall\Plugins\IpAddress;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\Plugins\VulnerabilityScore;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Tests that a rule which cannot match anything says so (#165).
 *
 * The failure this exists to end: a rule the evaluator cannot interpret returns
 * FALSE, which for a block plugin is indistinguishable from a rule that is
 * working and finding nothing. A typo produced silence, and silence reads as
 * "the detection is weak" rather than "the rule is wrong".
 */
class RuleDiagnosticsTest extends AbstractTestCase
{
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
        $logger = new Logger('rule-diagnostics');
        $logger->pushHandler($this->handler);
        LoggingFactory::setLogger($logger);
    }

    /**
     * The reasons reported while constructing a plugin from YAML config.
     *
     * @return array<int, string>
     */
    private function reasonsFor(string $class, string $yaml): array
    {
        new $class([], (array) Yaml::parse($yaml));

        $reasons = [];

        foreach ($this->handler->getRecords() as $record) {
            if ($record->level === Level::Warning && $record->message === 'Firewall rule will not match anything') {
                $reasons[] = (string) ($record->context['reason'] ?? '');
            }
        }

        return $reasons;
    }

    /**
     * A misspelled variable is named, with the variable it was probably meant
     * to be.
     */
    public function testTypoIsReportedWithASuggestion(): void
    {
        $reasons = $this->reasonsFor(UserAgent::class, '- "automatd:true"');

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('Unknown variable "automatd"', $reasons[0]);
        $this->assertStringContainsString('did you mean "automated"', $reasons[0]);
    }

    /**
     * A variable that is not close to anything lists what is available instead
     * of guessing.
     */
    public function testUnknownVariableListsTheAlternatives(): void
    {
        $reasons = $this->reasonsFor(UserAgent::class, '- "spaceship:true"');

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('Known variables:', $reasons[0]);
        $this->assertStringContainsString('automated', $reasons[0]);
    }

    /**
     * A string that is not rule-shaped at all is reported.
     */
    public function testUnparseableRuleIsReported(): void
    {
        $reasons = $this->reasonsFor(UserAgent::class, '- "nonsense"');

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('Not a recognisable rule', $reasons[0]);
    }

    /**
     * The YAML-map shape is accepted, and reported so the config gets fixed.
     *
     * `- automated: true` is what YAML looks like and reads as obviously
     * correct, which is exactly why it needs saying rather than silently
     * working or silently not.
     */
    public function testYamlMapShapeIsRepairedAndReported(): void
    {
        $reasons = $this->reasonsFor(UserAgent::class, '- automated: true');

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('Written as a YAML map', $reasons[0]);
        $this->assertStringContainsString('automated:true', $reasons[0]);
    }

    /**
     * ...and the repaired rule actually matches, which is the point.
     */
    public function testRepairedYamlMapRuleMatches(): void
    {
        $plugin = new UserAgent([], (array) Yaml::parse('- automated: true'));

        $request = Request::create('/', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.9',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)',
        ]);

        $this->assertTrue($plugin->evaluate($request));
    }

    /**
     * A map naming an unknown variable is reported rather than repaired.
     */
    public function testYamlMapWithUnknownVariableIsNotRepaired(): void
    {
        $reasons = $this->reasonsFor(UserAgent::class, '- automatd: true');

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('did you mean "automated"', $reasons[0]);
    }

    /**
     * Valid rules produce no noise, on every plugin that opts in.
     *
     * @param string $class
     *   Plugin class.
     * @param string $yaml
     *   A valid rule list.
     */
    #[DataProvider('validRuleProvider')]
    public function testValidRulesAreSilent(string $class, string $yaml): void
    {
        $this->assertSame([], $this->reasonsFor($class, $yaml));
    }

    /**
     * Rules that should pass without comment.
     */
    public static function validRuleProvider(): array
    {
        return [
            'user agent' => [UserAgent::class, "- \"automated:true\"\n- \"bot:true\"\n- \"client.name:Chrome\""],
            'user agent negated' => [UserAgent::class, '- "!bot:true"'],
            'url' => [Url::class, "- \"path@starts_with:/admin\"\n- \"header.user-agent@contains:WPScan\""],
            'url comparison' => [Url::class, '- "port > 8000"'],
            'url exists' => [Url::class, '- "query.cmd@exists"'],
            'asn' => [Asn::class, "- \"asn:13335\"\n- \"asn_org@contains:AMAZON\""],
        ];
    }

    /**
     * A bad rule nested inside a group is still named.
     */
    public function testNestedGroupRulesAreChecked(): void
    {
        $yaml = <<<YAML
        - type: AND
          rules:
            - "bot:true"
            - type: OR
              rules:
                - "client.name:Chrome"
                - "automatd:true"
        YAML;

        $reasons = $this->reasonsFor(UserAgent::class, $yaml);

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('did you mean "automated"', $reasons[0]);
    }

    /**
     * A structured rule's variable is checked too.
     */
    public function testStructuredRuleVariableIsChecked(): void
    {
        $yaml = "- variable: automatd\n  operator: equals\n  value: 'true'";

        $reasons = $this->reasonsFor(UserAgent::class, $yaml);

        $this->assertCount(1, $reasons);
        $this->assertStringContainsString('did you mean "automated"', $reasons[0]);
    }

    /**
     * Plugins whose config is not a rule list are skipped entirely.
     *
     * `IpAddress` takes bare addresses and `VulnerabilityScore` a nested
     * scoring tree. Checking either would report every single entry.
     */
    public function testPluginsWithoutRuleVocabularyAreNotChecked(): void
    {
        $this->assertSame([], $this->reasonsFor(IpAddress::class, "- 10.0.0.0/8\n- 192.168.1.1"));
        $this->assertSame([], $this->reasonsFor(VulnerabilityScore::class, "scoring:\n  methods:\n    GET: 0"));
    }

    /**
     * An empty rule list is not a problem.
     */
    public function testEmptyConfigIsSilent(): void
    {
        $this->assertSame([], $this->reasonsFor(UserAgent::class, '[]'));
    }

    /**
     * Several bad rules are each reported, so one fix does not hide the next.
     */
    public function testEveryBadRuleIsReported(): void
    {
        $reasons = $this->reasonsFor(
            UserAgent::class,
            "- \"automatd:true\"\n- \"nonsense\"\n- \"spaceship:true\""
        );

        $this->assertCount(3, $reasons);
    }

    /**
     * Checking happens once at construction, not on every request.
     */
    public function testCheckingHappensOncePerInstance(): void
    {
        $plugin = new UserAgent([], (array) Yaml::parse('- "automatd:true"'));
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']);

        $plugin->evaluate($request);
        $plugin->evaluate($request);
        $plugin->evaluate($request);

        $warnings = array_filter(
            $this->handler->getRecords(),
            static fn ($record): bool => $record->message === 'Firewall rule will not match anything'
        );

        $this->assertCount(1, $warnings);
    }
}
