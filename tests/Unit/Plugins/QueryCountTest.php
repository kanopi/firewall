<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\Url;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * `query_count`: how many values the client sent for a query parameter (#440).
 *
 * The case is facet crawling -- `?f[0]=…&f[1]=…&f[2]=…&f[3]=…` in every combination, each
 * an uncacheable faceted search. There was no way to cap it that a bot could not spell
 * around: a list under `query.f` resolves to NULL, PHP keeps only the last of `f=a&f=b`,
 * and the regex workaround missed repeated names and anything interleaved.
 */
final class QueryCountTest extends AbstractTestCase
{
    private function valuesIn(string $uri, string $variable = 'query_count.f'): mixed
    {
        $plugin = new class([], []) extends Url {
            public function read(Request $request, string $variable): mixed
            {
                return $this->resolveRequestValue($request, $variable);
            }
        };

        return $plugin->read(Request::create($uri), $variable);
    }

    /**
     * Every way of sending a value counts the same.
     *
     * @param string $query
     *   The query string.
     * @param int $expected
     *   How many values of `f` it carries.
     */
    #[DataProvider('spellings')]
    public function testEverySpellingCounts(string $query, int $expected): void
    {
        $this->assertSame($expected, $this->valuesIn('/search?' . $query));
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function spellings(): array
    {
        return [
            'indexed' => ['f[0]=a&f[1]=b&f[2]=c&f[3]=d', 4],
            'empty brackets' => ['f[]=a&f[]=b&f[]=c&f[]=d', 4],
            'sparse keys' => ['f[0]=a&f[7]=b&f[8]=c&f[9]=d', 4],
            'named keys' => ['f[x]=a&f[y]=b&f[z]=c&f[w]=d', 4],
            // PHP's parsed query keeps only the last of these.
            'repeated plain' => ['f=a&f=b&f=c&f=d', 4],
            'encoded brackets' => ['f%5B0%5D=a&f%5B1%5D=b&f%5B2%5D=c&f%5B3%5D=d', 4],
            'interleaved with others' => ['f[0]=a&q=x&f[1]=b&page=2&f[2]=c&sort=d&f[3]=d', 4],
            'mixed spellings' => ['f[0]=a&f[]=b&f[x]=c&f=d', 4],
            'nested counts once per pair' => ['f[x][y]=a&f[x][z]=b', 2],
            'a value-less parameter counts' => ['f&f[]=b', 2],
            'three' => ['f[]=a&f[]=b&f[]=c', 3],
            'another name only' => ['g[]=a&g[]=b', 0],
            // A name that merely starts with f is a different parameter.
            'a longer name' => ['facet=a&ff=b&f_x=c', 0],
            // Names are case-sensitive, as the application reads them.
            'another case' => ['F[]=a&F[]=b', 0],
            'stray separators and empty names' => ['&&f=a&=x&&f[]=b&', 2],
        ];
    }

    public function testAnAbsentParameterIsZero(): void
    {
        $this->assertSame(0, $this->valuesIn('/search'));
        $this->assertSame(0, $this->valuesIn('/search?q=x'));
    }

    /**
     * With no name, every parameter.
     */
    public function testTheTotalCountsEveryParameter(): void
    {
        $this->assertSame(5, $this->valuesIn('/search?f[]=a&f[]=b&q=x&page=2&sort', 'query_count'));
        $this->assertSame(0, $this->valuesIn('/search', 'query_count'));
    }

    /**
     * A name containing a dot is read whole, although the rule syntax splits on dots.
     */
    public function testANameWithADot(): void
    {
        $this->assertSame(2, $this->valuesIn('/search?filter.type=a&filter.type=b', 'query_count.filter.type'));
    }

    /**
     * Without QUERY_STRING in the server bag, as some bridges build a request, the request
     * URI's query is counted instead.
     */
    public function testTheRequestUriIsTheFallback(): void
    {
        $plugin = new class([], []) extends Url {
            public function read(Request $request, string $variable): mixed
            {
                return $this->resolveRequestValue($request, $variable);
            }
        };

        $request = new Request([], [], [], [], [], ['REQUEST_URI' => '/search?f=a&f=b&f=c']);

        $this->assertSame(3, $plugin->read($request, 'query_count.f'));
    }

    // -----------------------------------------------------------------------
    // As a rule
    // -----------------------------------------------------------------------

    private function firewall(string $rule): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                'response' => 'block',
                'enable' => true,
                'config' => [$rule],
            ]],
        ]]);
    }

    private function refuses(Firewall $firewall, string $uri): bool
    {
        try {
            $firewall->evaluate(Request::create($uri, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.9']));

            return false;
        } catch (FirewallBlockedException) {
            return true;
        }
    }

    /**
     * The rule from the recipe: more than three facets.
     */
    public function testMoreThanThreeFacetsIsRefused(): void
    {
        $rule = 'query_count.f@greater_than:3';

        // A fresh firewall each time: a block also bans the address, which is
        // why the recipe recommends challenge, or `metadata.record: false`.
        $this->assertFalse($this->refuses($this->firewall($rule), '/search?f[0]=a&f[1]=b&f[2]=c'));
        $this->assertTrue($this->refuses($this->firewall($rule), '/search?f[0]=a&f[7]=b&q=x&f[x]=c&f=d'));
        $this->assertFalse($this->refuses($this->firewall($rule), '/search'));
    }

    /**
     * A blunt cap on every parameter.
     */
    public function testATotalCap(): void
    {
        $this->assertFalse($this->refuses($this->firewall('query_count@greater_than:4'), '/search?a=1&b=2&c=3&d=4'));
        $this->assertTrue($this->refuses($this->firewall('query_count@greater_than:4'), '/search?a=1&b=2&c=3&d=4&e=5'));
    }

    /**
     * The URL plugin knows the variable, so a rule on it is not reported as unusable.
     */
    public function testTheVariableIsKnown(): void
    {
        $method = new \ReflectionMethod(Url::class, 'knownRuleVariables');

        $this->assertContains('query_count', $method->invoke(new Url([], [])));
    }
}
