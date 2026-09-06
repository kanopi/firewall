<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Utility;

use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\RuleDiagnostics;

/**
 * Covers the diagnostic shapes the plugin-level suite does not produce.
 */
class RuleDiagnosticsEdgeTest extends AbstractTestCase
{
    /**
     * The known vocabulary used throughout.
     *
     * @var array<int, string>
     */
    private const KNOWN = ['automated', 'bot', 'client'];

    /**
     * With no vocabulary declared, nothing is inspected at all.
     *
     * This is the guard that keeps IpAddress and VulnerabilityScore — whose
     * config is not a rule list — from having every entry reported.
     */
    public function testEmptyVocabularySkipsInspection(): void
    {
        $rules = ['10.0.0.0/8', 'not a rule either'];

        $result = RuleDiagnostics::inspect($rules, []);

        $this->assertSame($rules, $result['rules']);
        $this->assertSame([], $result['issues']);
    }

    /**
     * A map with several keys is not a rule in any supported shape.
     */
    public function testMultiKeyMapIsReported(): void
    {
        $result = RuleDiagnostics::inspect([['automated' => true, 'bot' => true]], self::KNOWN);

        $this->assertCount(1, $result['issues']);
        $this->assertStringContainsString('Not a recognisable rule', $result['issues'][0]['reason']);
    }

    /**
     * A single-key map whose value is itself a structure is not a rule either.
     */
    public function testSingleKeyMapWithAnArrayValueIsReported(): void
    {
        $result = RuleDiagnostics::inspect([['automated' => ['yes']]], self::KNOWN);

        $this->assertCount(1, $result['issues']);
        $this->assertSame('automated', $result['issues'][0]['rule']);
        $this->assertStringContainsString('Not a recognisable rule', $result['issues'][0]['reason']);
    }

    /**
     * An entry that is not a string or a map at all is reported by type.
     *
     * @param mixed $rule
     *   Something that is not a rule.
     * @param string $type
     *   The type name the message should carry.
     */
    public function testNonStringNonArrayRulesAreReportedByType(): void
    {
        foreach ([[42, 'int'], [true, 'bool'], [1.5, 'float']] as [$rule, $type]) {
            $result = RuleDiagnostics::inspect([$rule], self::KNOWN);

            $this->assertCount(1, $result['issues']);
            $this->assertStringContainsString($type, $result['issues'][0]['reason']);
        }
    }

    /**
     * An empty rule string is reported rather than parsed.
     */
    public function testEmptyRuleIsReported(): void
    {
        $result = RuleDiagnostics::inspect(['', '   ', '!'], self::KNOWN);

        $this->assertCount(3, $result['issues']);

        foreach ($result['issues'] as $issue) {
            $this->assertSame('Empty rule.', $issue['reason']);
        }
    }

    /**
     * A structured rule with a non-string variable is left alone rather than
     * guessed at.
     */
    public function testStructuredRuleWithNonStringVariableIsNotInspected(): void
    {
        $rule = ['variable' => 42, 'operator' => 'equals', 'value' => 'x'];

        $result = RuleDiagnostics::inspect([$rule], self::KNOWN);

        $this->assertSame([], $result['issues']);
    }

    /**
     * A repaired map rule comes back as the string the evaluator understands.
     */
    public function testRepairedRuleIsReturnedAsAString(): void
    {
        $result = RuleDiagnostics::inspect([['automated' => true]], self::KNOWN);

        $this->assertSame(['automated:true'], $result['rules']);
    }

    /**
     * Values of every scalar type render into the rule syntax.
     *
     * @param mixed $value
     *   The configured value.
     * @param string $expected
     *   The rule it should become.
     */
    public function testScalarValuesRenderIntoRuleSyntax(): void
    {
        $cases = [
            [true, 'automated:true'],
            [false, 'automated:false'],
            ['Chrome', 'automated:Chrome'],
            [10, 'automated:10'],
            [null, 'automated:'],
        ];

        foreach ($cases as [$value, $expected]) {
            $result = RuleDiagnostics::inspect([['automated' => $value]], self::KNOWN);

            $this->assertSame([$expected], $result['rules']);
        }
    }

    /**
     * Matching is case-insensitive, so `Bot:true` is not reported as unknown.
     */
    public function testVariableMatchingIsCaseInsensitive(): void
    {
        $this->assertSame([], RuleDiagnostics::inspect(['Bot:true', 'AUTOMATED:true'], self::KNOWN)['issues']);
    }
}
