<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\Url;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Equality between a number from the request and a number written as text (#443).
 *
 * `port`, `query_count`, `asn` and GeoLocation's database fields resolve to an int or a
 * float, and every rule value is a string -- from YAML, or from a rule source's `{value}`.
 * Compared strictly, `port:8443` never matched port 8443, and `not_equals` matched every
 * request, so a block rule on `query_count.f@not_equals:0` refused everybody.
 */
final class NumericEqualityTest extends AbstractTestCase
{
    /**
     * @param array<string, mixed> $metadata
     */
    private function refuses(mixed $rule, string $uri, array $metadata = []): bool
    {
        $firewall = Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                'response' => 'block',
                'enable' => true,
                'metadata' => $metadata + ['record' => false],
                'config' => $rule === null ? [] : [$rule],
            ]],
        ]]);

        try {
            $firewall->evaluate(Request::create($uri, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));

            return false;
        } catch (FirewallBlockedException) {
            return true;
        }
    }

    private const FOUR_FACETS = '/s?f[]=a&f[]=b&f[]=c&f[]=d';

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function rules(): array
    {
        return [
            'port equals' => ['port@equals:8443', 'https://h:8443/', true],
            'port shorthand' => ['port:8443', 'https://h:8443/', true],
            'port in a list' => ['port@in:8443,9443', 'https://h:8443/', true],
            'port not in the list' => ['port@in:80,9443', 'https://h:8443/', false],
            'port not_equals itself' => ['port@not_equals:8443', 'https://h:8443/', false],
            'port not_equals another' => ['port@not_equals:9443', 'https://h:8443/', true],
            'query_count equals' => ['query_count.f@equals:4', self::FOUR_FACETS, true],
            'query_count in' => ['query_count.f@in:4,5', self::FOUR_FACETS, true],
            'query_count not_equals itself' => ['query_count.f@not_equals:4', self::FOUR_FACETS, false],
            // The lockout: this blocked every request.
            'not_equals 0 with none present' => ['query_count.f@not_equals:0', '/s', false],
            'not_equals 0 with some present' => ['query_count.f@not_equals:0', self::FOUR_FACETS, true],
            'padded value' => ['port@equals: 8443 ', 'https://h:8443/', true],
            // A value that is not a number is compared as before.
            'not a number' => ['port@equals:abc', 'https://h:8443/', false],
            'not_equals not a number' => ['port@not_equals:abc', 'https://h:8443/', true],
            // Two strings stay strict, so a text variable is unchanged.
            'text stays strict' => ['query.page:01', '/s?page=1', false],
            'text equal' => ['query.page:1', '/s?page=1', true],
            'numeric operators unchanged' => ['port@greater_than:8000', 'https://h:8443/', true],
        ];
    }

    #[DataProvider('rules')]
    public function testEqualityOnANumber(string $rule, string $uri, bool $refused): void
    {
        $this->assertSame($refused, $this->refuses($rule, $uri));
    }

    /**
     * A rule source substitutes `{value}` after the config is built, so the host cannot
     * cast it; the comparison has to.
     */
    public function testARuleSourceValueMatchesANumber(): void
    {
        $dir = sys_get_temp_dir() . '/fw-443-' . bin2hex(random_bytes(6));
        mkdir($dir);
        file_put_contents($dir . '/ports.txt', "8443\n9443\n");
        file_put_contents($dir . '/counts.txt', "4\n");

        try {
            $ports = ['sources' => [['name' => 'ports-' . basename($dir), 'upstream' => $dir . '/ports.txt', 'template' => 'port:{value}']]];
            $this->assertTrue($this->refuses(null, 'https://h:8443/', $ports));
            $this->assertFalse($this->refuses(null, 'https://h:7000/', $ports));

            $counts = ['sources' => [['name' => 'counts-' . basename($dir), 'upstream' => $dir . '/counts.txt', 'template' => 'query_count.f:{value}']]];
            $this->assertTrue($this->refuses(null, self::FOUR_FACETS, $counts));
            $this->assertFalse($this->refuses(null, '/s?f[]=a', $counts));
        } finally {
            @unlink($dir . '/ports.txt');
            @unlink($dir . '/counts.txt');
            @rmdir($dir);
        }
    }

    /**
     * The comparison itself, for the float a GeoLocation database field returns.
     *
     * @param mixed $requestValue
     *   The resolved value.
     * @param string $operator
     *   The operator.
     * @param string $value
     *   The rule's value.
     * @param bool $expected
     *   The result.
     */
    #[DataProvider('comparisons')]
    public function testTheComparison(mixed $requestValue, string $operator, string $value, bool $expected): void
    {
        $plugin = new class([], []) extends Url {
            public function compare(mixed $requestValue, string $operator, string $value): bool
            {
                return $this->evaluateComparison($requestValue, $operator, $value);
            }
        };

        $this->assertSame($expected, $plugin->compare($requestValue, $operator, $value));
    }

    /**
     * @return array<string, array{mixed, string, string, bool}>
     */
    public static function comparisons(): array
    {
        return [
            'a latitude' => [51.5074, 'equals', '51.5074', true],
            'a latitude written longer' => [51.5074, 'equals', '51.50740', true],
            'another latitude' => [51.5074, 'equals', '51.5075', false],
            'an int against a decimal' => [10, 'equals', '10.0', true],
            'not_equals on a float' => [51.5074, 'not_equals', '51.5074', false],
            'a numeric string request stays strict' => ['10', 'equals', '10.0', false],
            'trailing text is not a number' => [8443, 'equals', '8443abc', false],
        ];
    }
}
