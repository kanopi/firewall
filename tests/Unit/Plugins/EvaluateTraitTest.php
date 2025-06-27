<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;
use Kanopi\Firewall\Plugins\EvaluateTrait;

class EvaluateTraitTest extends AbstractTestCase
{
    /**
     * Anonymous plugin using the EvaluateTrait with getValue override.
     */
    protected function getMockPlugin(array $variables = []): object {
        return new class($variables) implements PluginInterface {
            use EvaluateTrait;
            private array $vars;
            public function __construct(array $vars) {
                $this->vars = $vars;
            }
            public function getName(): string {
                return 'Mock Plugin';
            }

            public function getDescription(): string {
                return 'Mock Plugin Description';
            }

            protected function getValue(Request $request, string $key): mixed {
                return $this->vars[$key] ?? null;
            }

            public function evaluate(Request $request): bool {
                return true;
            }

            public function getStatusCode(?Request $requst = null): int {
                return 400;
            }
            public function getExpirationTime(?Request $requst = null): int {
                return 0;
            }
        };
    }

    /**
     * Plugin with no getValue method — fallback to null.
     */
    protected function getPluginWithoutGetValue(): object {
        return new class {
            use EvaluateTrait;
        };
    }

    /** Test evaluateRequest returns true if any rule matches */
    public function testEvaluateRequestReturnsTrueOnFirstMatch(): void {
        $plugin = $this->getMockPlugin(['method' => 'POST']);
        $request = Request::create('/');
        $rules = [
            ['variable' => 'method', 'operator' => 'equals', 'value' => 'POST'],
            ['variable' => 'method', 'operator' => 'equals', 'value' => 'GET'],
        ];
        $this->assertTrue($this->invoke($plugin, 'evaluateRequest', [$request, $rules]));
    }

    /** Test evaluateRequest returns false if no rules match */
    public function testEvaluateRequestReturnsFalseIfNoMatch(): void {
        $plugin = $this->getMockPlugin(['method' => 'PATCH']);
        $request = Request::create('/');
        $rules = [
            ['variable' => 'method', 'operator' => 'equals', 'value' => 'POST'],
            ['variable' => 'method', 'operator' => 'equals', 'value' => 'GET'],
        ];
        $this->assertFalse($this->invoke($plugin, 'evaluateRequest', [$request, $rules]));
    }

    /** Test simple rule parsing and match */
    public function testSimpleEqualsMatch(): void {
        $plugin = $this->getMockPlugin(['host' => 'example.com']);
        $request = Request::create('/');
        $this->assertTrue($this->invoke($plugin, 'evaluateSimpleStringRule', [$request, 'host:example.com']));
    }

    /** Test simple rule with negation */
    public function testSimpleNegation(): void {
        $plugin = $this->getMockPlugin(['host' => 'example.com']);
        $request = Request::create('/');
        $this->assertFalse($this->invoke($plugin, 'evaluateSimpleStringRule', [$request, '!host:example.com']));
    }

    /** Test parseSimpleStringRule with @operator syntax */
    public function testParseOperatorFormat(): void {
        $plugin = $this->getMockPlugin();
        $rule = $this->invoke($plugin, 'parseSimpleStringRule', ['x@contains:abc']);
        $this->assertSame('x', $rule['variable']);
        $this->assertSame('contains', $rule['operator']);
        $this->assertSame('abc', $rule['value']);
    }

    /** Test parseSimpleStringRule with numeric comparison shorthand */
    public function testParseShorthandOperator(): void {
        $plugin = $this->getMockPlugin();
        $rule = $this->invoke($plugin, 'parseSimpleStringRule', ['score >= 90']);
        $this->assertSame('greater_than_or_equal', $rule['operator']);
        $this->assertSame('score', $rule['variable']);
        $this->assertSame('90', $rule['value']);
    }

    /**
     * Test the in operator to make sure it converts to a equal operator without matches.
     */
    public function testInOperator(): void {
        $plugin = $this->getMockPlugin(['tag' => 'green']);
        $request = Request::create('/');

        $rule = [
            'variable' => 'tag',
            'operator' => 'in',
            'value' => ['green', 'blue'],
        ];
        $this->assertTrue($this->invoke($plugin, 'evaluateStructuredRule', [$request, $rule]), "Failed for in operator");

        $plugin = $this->getMockPlugin(['tag' => 'green']);
        $request = Request::create('/');

        $rule = [
            'variable' => 'tag',
            'operator' => 'in',
            'value' => ['red'],
        ];
        $this->assertFalse($this->invoke($plugin, 'evaluateStructuredRule', [$request, $rule]), "Failed for red");
    }

    /** Test all match modes for arrays */
    public function testMatchModes(): void {
        $plugin = $this->getMockPlugin(['tag' => 'green']);
        $request = Request::create('/');
        $modes = [
            'any' => true,
            'all' => false,
            'none' => false,
            'some' => true,
        ];

        foreach ($modes as $mode => $expected) {
            $rule = [
                'variable' => 'tag',
                'operator' => 'equals',
                'value' => ['green', 'blue'],
                'matches' => $mode,
            ];
            $this->assertSame($expected, $this->invoke($plugin, 'evaluateStructuredRule', [$request, $rule]), "Failed for $mode");
        }
    }

    /** Test group rules with AND */
    public function testEvaluateGroupAND(): void {
        $plugin = $this->getMockPlugin(['a' => 'x', 'b' => 'y']);
        $request = Request::create('/');
        $group = [
            'type' => 'AND',
            'rules' => [
                ['variable' => 'a', 'operator' => 'equals', 'value' => 'x'],
                ['variable' => 'b', 'operator' => 'equals', 'value' => 'y'],
            ]
        ];
        $this->assertTrue($this->invoke($plugin, 'evaluateGroup', [$request, $group]));
    }

    /** Test group rules with OR */
    public function testEvaluateGroupOR(): void {
        $plugin = $this->getMockPlugin(['a' => 'no', 'b' => 'yes']);
        $request = Request::create('/');
        $group = [
            'type' => 'OR',
            'rules' => [
                ['variable' => 'a', 'operator' => 'equals', 'value' => 'yes'],
                ['variable' => 'b', 'operator' => 'equals', 'value' => 'yes'],
            ]
        ];
        $this->assertTrue($this->invoke($plugin, 'evaluateGroup', [$request, $group]));
    }

    /** Test group rule with invalid type returns false */
    public function testEvaluateGroupInvalidType(): void {
        $plugin = $this->getMockPlugin(['x' => 'a']);
        $request = Request::create('/');
        $group = ['type' => 'WRONG', 'rules' => [['variable' => 'x', 'operator' => 'equals', 'value' => 'a']]];
        $this->assertFalse($this->invoke($plugin, 'evaluateGroup', [$request, $group]));
    }

    /** Test fallback in getRequestValue if variable is empty */
    public function testGetRequestValueEmptyKey(): void {
        $plugin = $this->getMockPlugin();
        $request = Request::create('/');
        $this->assertNull($this->invoke($plugin, 'getRequestValue', [$request, ' ']));
    }

    /** Test fallback in getRequestValue if no getValue method */
    public function testGetRequestValueMissingMethod(): void {
        $plugin = $this->getPluginWithoutGetValue();
        $request = Request::create('/');
        $this->assertNull($this->invoke($plugin, 'getRequestValue', [$request, 'anything']));
    }

    /**
     * Helper method to invoke protected methods.
     */
    private function invoke(object $object, string $method, array $args = []): mixed {
        $ref = new \ReflectionObject($object);
        $m = $ref->getMethod($method);
        $m->setAccessible(true);
        return $m->invokeArgs($object, $args);
    }

    /** Test evaluateRule with a string rule */
    public function testEvaluateRuleWithString(): void {
        $plugin = $this->getMockPlugin(['method' => 'POST']);
        $request = Request::create('/', 'POST');

        $this->assertTrue(
            $this->invoke($plugin, 'evaluateRule', [$request, 'method:POST']),
            'Should return true for string-based rule that matches'
        );
    }

    /** Test evaluateRule with a group rule */
    public function testEvaluateRuleWithGroup(): void {
        $plugin = $this->getMockPlugin(['x' => 'y']);
        $request = Request::create('/');
        $rule = [
            'type' => 'AND',
            'rules' => [
                ['variable' => 'x', 'operator' => 'equals', 'value' => 'y']
            ]
        ];

        $this->assertTrue(
            $this->invoke($plugin, 'evaluateRule', [$request, $rule]),
            'Should evaluate group rules properly'
        );
    }

    /** Test evaluateRule with invalid rule returns false */
    public function testEvaluateRuleWithInvalidInput(): void {
        $plugin = $this->getMockPlugin();
        $request = Request::create('/');

        // Invalid format — neither string nor structured array
        $invalid = ['foo' => 'bar'];

        $this->assertFalse(
            $this->invoke($plugin, 'evaluateRule', [$request, $invalid]),
            'Should return false for unknown rule format'
        );
    }

    /** Test evaluateGroup returns false for AND when a sub-rule fails */
    public function testEvaluateGroupAndFails(): void {
        $plugin = $this->getMockPlugin(['x' => 'fail']);
        $request = Request::create('/');
        $rule = [
            'type' => 'AND',
            'rules' => [
                ['variable' => 'x', 'operator' => 'equals', 'value' => 'pass'],
            ],
        ];

        $this->assertFalse(
            $this->invoke($plugin, 'evaluateGroup', [$request, $rule]),
            'AND group should return false if any sub-rule fails'
        );
    }

    /** Test evaluateGroup returns false for OR when no sub-rule passes */
    public function testEvaluateGroupOrFails(): void {
        $plugin = $this->getMockPlugin(['x' => 'no-match']);
        $request = Request::create('/');
        $rule = [
            'type' => 'OR',
            'rules' => [
                ['variable' => 'x', 'operator' => 'equals', 'value' => 'other'],
            ],
        ];

        $this->assertFalse(
            $this->invoke($plugin, 'evaluateGroup', [$request, $rule]),
            'OR group should return false if no sub-rule passes'
        );
    }

    /** Test evaluateGroup returns false for unsupported type */
    public function testEvaluateGroupInvalidTypeAnother(): void {
        $plugin = $this->getMockPlugin();
        $request = Request::create('/');
        $rule = [
            'type' => 'XOR', // not supported
            'rules' => [
                ['variable' => 'a', 'operator' => 'equals', 'value' => 'b'],
            ],
        ];

        $this->assertFalse(
            $this->invoke($plugin, 'evaluateGroup', [$request, $rule]),
            'Should return false for unknown group type'
        );
    }

    public function testEvaluateSimpleStringRuleInvalidFormat(): void {
        $plugin = $this->getMockPlugin();
        $request = Request::create('/');

        // Missing colon => invalid format
        $invalidRule = 'invalidrule';

        $result = $this->invoke($plugin, 'evaluateSimpleStringRule', [$request, $invalidRule]);

        $this->assertFalse($result, 'evaluateSimpleStringRule should return false for invalid format');
    }

    public function testEvaluateComparisonLowercasesArrayWhenNotCaseSensitive(): void {
        $plugin = $this->getMockPlugin();

        $requestValue = 'Foo';
        $value = ['foo', 'bar'];

        $result = $this->invoke($plugin, 'evaluateComparison', [$requestValue, 'in', $value, false]);
        $this->assertTrue($result);
    }

    public function testEvaluateComparisonEqualsCaseInsensitive(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', ['Foo', 'equals', 'foo', false]));
    }

    public function testEvaluateComparisonEqualsCaseSensitive(): void {
        $plugin = $this->getMockPlugin();
        $this->assertFalse($this->invoke($plugin, 'evaluateComparison', ['Foo', 'equals', 'foo', true]));
    }

    public function testEvaluateComparisonStartsWith(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', ['foobar', 'starts_with', 'foo', false]));
    }

    public function testEvaluateComparisonEndsWith(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', ['foobar', 'ends_with', 'bar', false]));
    }

    public function testEvaluateComparisonContains(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', ['foobar', 'contains', 'oba', false]));
    }

    public function testEvaluateComparisonRegex(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', ['abc123', 'regex', '/[a-z]+/', false]));
    }

    public function testEvaluateComparisonRegexInvalid(): void {
        $plugin = $this->getMockPlugin();
        // invalid regex pattern
        $this->assertFalse($this->invoke($plugin, 'evaluateComparison', ['abc', 'regex', '/[a-z/', false]));
    }

    public function testEvaluateComparisonGreaterThan(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', [10, 'greater_than', 5, false]));
    }

    public function testEvaluateComparisonLessThan(): void {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', [3, 'less_than', 5, false]));
    }

    public function testEvaluateComparisonUnknownOperatorReturnsFalse(): void {
        $plugin = $this->getMockPlugin();
        $this->assertFalse($this->invoke($plugin, 'evaluateComparison', ['foo', 'invalid_operator', 'bar', false]));
    }

    public function testGreaterThanOrEqual(): void
    {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', [5, 'greater_than_or_equal', 5, false]));
    }

    public function testLessThanOrEqual(): void
    {
        $plugin = $this->getMockPlugin();
        $this->assertTrue($this->invoke($plugin, 'evaluateComparison', [5, 'less_than_or_equal', 6, false]));
    }

    public function testParseSimpleStringRuleCoversAllBranches(): void
    {
        $plugin = $this->getMockPlugin();

        // Negation
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['!method:POST']);
        $this->assertTrue($result['negate'], 'Negation not detected');
        $this->assertSame('method', $result['variable']);
        $this->assertSame('POST', $result['value']);
        $this->assertSame('equals', $result['operator']);

        // Explicit operator with @
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['path@starts_with:/admin']);
        $this->assertSame('starts_with', $result['operator']);
        $this->assertSame('/admin', $result['value']);

        // Comparison syntax
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['score>=5']);
        $this->assertSame('greater_than_or_equal', $result['operator']);
        $this->assertSame('score', $result['variable']);
        $this->assertSame('5', $result['value']);

        // Default fallback
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['host:example.com']);
        $this->assertSame('equals', $result['operator']);
        $this->assertSame('example.com', $result['value']);

        // Match mode
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['tags@contains:one,two#all']);
        $this->assertSame(['one', 'two'], $result['value']);
        $this->assertSame('all', $result['matches']);

        // Invalid match suffix should ignore it
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['tags@contains:one,two#bogus']);
        $this->assertNull($result['matches']);

        // Value is converted to array
        $result = $this->invoke($plugin, 'parseSimpleStringRule', ['query@in:one,two,three']);
        $this->assertSame(['one', 'two', 'three'], $result['value']);
    }
}
