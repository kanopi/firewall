<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Traits;

use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Asserts that every rule form the documentation promises actually fires.
 *
 * Four documented constructs were silently doing nothing when this was written
 * (#169): `header.*` resolution, the `exists` operator, the `not_equals`
 * operator, and the shorthand numeric comparisons. Each failed closed and said
 * nothing, so a rule written straight out of the docs had simply never matched.
 *
 * The point of this file is that the operator list in
 * `docs/configuration/conditional-logic.md` and the variable list in
 * `docs/plugins/url.md` stay executable rather than aspirational.
 */
class DocumentedRuleFormsTest extends AbstractTestCase
{
    /**
     * A request carrying something for every documented variable to read.
     */
    private function request(): Request
    {
        return Request::create(
            '/api/users?cmd=ls&n=5&flag=&action=delete',
            'POST',
            ['username' => 'admin'],
            ['session' => 'abc123'],
            [],
            [
                'REMOTE_ADDR' => '203.0.113.9',
                'HTTP_USER_AGENT' => 'WPScan v3.8.22',
                'HTTP_HOST' => 'example.com',
            ]
        );
    }

    /**
     * Evaluate one rule against that request.
     */
    private function ruleMatches(string $rule): bool
    {
        return (new Url([], [$rule]))->evaluate($this->request());
    }

    /**
     * Every operator in the documented list behaves as documented.
     *
     * @param string $rule
     *   The rule under test.
     * @param bool $expected
     *   Whether it should match.
     */
    #[DataProvider('operatorProvider')]
    public function testDocumentedOperators(string $rule, bool $expected): void
    {
        $this->assertSame($expected, $this->ruleMatches($rule), $rule);
    }

    /**
     * The operator list from `docs/configuration/conditional-logic.md`.
     */
    public static function operatorProvider(): array
    {
        return [
            'equals (default)' => ['method:POST', true],
            'equals negative' => ['method:GET', false],
            'not_equals' => ['method@not_equals:GET', true],
            'not_equals negative' => ['method@not_equals:POST', false],
            'contains' => ['path@contains:users', true],
            'starts_with' => ['path@starts_with:/api', true],
            'ends_with' => ['path@ends_with:users', true],
            'regex' => ['path@regex:#^/api/#', true],
            'in' => ['method@in:POST,PUT', true],
            'in negative' => ['method@in:GET,HEAD', false],
            'greater_than' => ['query.n@greater_than:1', true],
            'less_than' => ['query.n@less_than:9', true],
            'greater_than_or_equal' => ['query.n@greater_than_or_equal:5', true],
            'less_than_or_equal' => ['query.n@less_than_or_equal:5', true],
            'exists' => ['query.cmd@exists', true],
            'exists on an absent variable' => ['query.nope@exists', false],
            'exists on an empty value' => ['query.flag@exists', true],
            'negated exists' => ['!query.nope@exists', true],
        ];
    }

    /**
     * The shorthand numeric comparisons documented alongside the operators.
     *
     * These carry no colon, which is what the format gate used to reject.
     *
     * @param string $rule
     *   The rule under test.
     * @param bool $expected
     *   Whether it should match.
     */
    #[DataProvider('shorthandComparisonProvider')]
    public function testShorthandComparisons(string $rule, bool $expected): void
    {
        $this->assertSame($expected, $this->ruleMatches($rule), $rule);
    }

    /**
     * Forms like `client.version <= 10` from the documentation.
     */
    public static function shorthandComparisonProvider(): array
    {
        return [
            'greater or equal, tight' => ['query.n>=5', true],
            'greater, spaced' => ['query.n > 1', true],
            'less, tight' => ['query.n<9', true],
            'less or equal, false' => ['query.n<=4', false],
            'greater, false' => ['query.n > 99', false],
        ];
    }

    /**
     * Header variables resolve, in any casing.
     *
     * Symfony stores each header as a *list* of values because HTTP permits
     * repeats. Returning that array unjoined is what made every `header.*`
     * rule match nothing.
     *
     * @param string $rule
     *   The rule under test.
     * @param bool $expected
     *   Whether it should match.
     */
    #[DataProvider('headerRuleProvider')]
    public function testHeaderRules(string $rule, bool $expected): void
    {
        $this->assertSame($expected, $this->ruleMatches($rule), $rule);
    }

    /**
     * Header forms, including the two `presets/wordpress.yml` ships.
     */
    public static function headerRuleProvider(): array
    {
        return [
            'lowercase name' => ['header.user-agent@contains:WPScan', true],
            'canonical casing' => ['header.User-Agent@contains:WPScan', true],
            'upper casing' => ['header.USER-AGENT@contains:WPScan', true],
            'regex, as wordpress.yml ships it' => [
                'header.user-agent@regex:/wp[_-]?(scan|vuln|exploit)/i',
                true,
            ],
            'host header' => ['header.host@contains:example.com', true],
            'exists on a present header' => ['header.user-agent@exists', true],
            'exists on an absent header' => ['header.x-forwarded-for@exists', false],
            'negated exists on an absent header' => ['!header.x-forwarded-for@exists', true],
            'no false positive' => ['header.user-agent@contains:Googlebot', false],
        ];
    }

    /**
     * The other documented variable roots still resolve.
     *
     * @param string $rule
     *   The rule under test.
     */
    #[DataProvider('variableRootProvider')]
    public function testDocumentedVariableRoots(string $rule): void
    {
        $this->assertTrue($this->ruleMatches($rule), $rule);
    }

    /**
     * Roots listed in `docs/plugins/url.md`.
     */
    public static function variableRootProvider(): array
    {
        return array_map(static fn (string $rule): array => [$rule], [
            'method:POST',
            'host:example.com',
            'path:/api/users',
            'scheme:http',
            'query.action:delete',
            'post.username:admin',
            'cookie.session:abc123',
        ]);
    }

    /**
     * A rule in none of the supported shapes is still refused rather than
     * loosely interpreted.
     *
     * @param string $rule
     *   The rule under test.
     */
    #[DataProvider('unparseableProvider')]
    public function testUnparseableRulesDoNotMatch(string $rule): void
    {
        $this->assertFalse($this->ruleMatches($rule), $rule);
    }

    /**
     * Strings that are not rules.
     */
    public static function unparseableProvider(): array
    {
        return array_map(static fn (string $rule): array => [$rule], [
            'nonsense',
            'just some words',
            '',
        ]);
    }

    /**
     * Grouped rules combine the fixed forms correctly.
     */
    public function testGroupedRulesUseTheFixedForms(): void
    {
        $plugin = new Url([], [
            [
                'type' => 'AND',
                'rules' => [
                    'method:POST',
                    'path@starts_with:/api',
                    '!header.authorization@exists',
                ],
            ],
        ]);

        $this->assertTrue(
            $plugin->evaluate($this->request()),
            'The documented AND group from docs/plugins/url.md must fire.'
        );
    }
}
