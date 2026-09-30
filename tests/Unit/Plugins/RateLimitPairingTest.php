<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Limiting one path by account and by address (#424).
 *
 * The docs recommend both, because they catch opposite attacks. They showed the pair as
 * two entries in one rule's `config:`, where a rate limit uses the first entry whose path
 * matches and stops -- so the address limit never ran. These pin both halves: the pair
 * works as two rules, and does not as one.
 */
final class RateLimitPairingTest extends AbstractTestCase
{
    /**
     * @param array<int, array<string, mixed>> $plugins
     */
    private function attempts(array $plugins): string
    {
        $firewall = Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => $plugins,
        ]]);

        $out = [];

        // One address, five different accounts.
        foreach (['a', 'b', 'c', 'd', 'e'] as $name) {
            try {
                $firewall->evaluate(Request::create('/login', 'POST', ['name' => $name], [], [], ['REMOTE_ADDR' => '203.0.113.9']));
                $out[] = 'ok';
            } catch (FirewallBlockedException) {
                $out[] = 'refused';
            }
        }

        return implode(',', $out);
    }

    private function rule(array ...$entries): array
    {
        return [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
            'response' => 'block',
            'enable' => true,
            'config' => $entries,
        ];
    }

    private const BY_ACCOUNT = ['path' => '/login', 'rate' => 5, 'sample' => 300, 'key' => ['post.name']];

    private const BY_ADDRESS = ['path' => '/login', 'rate' => 2, 'sample' => 300];

    public function testAsTwoRulesTheAddressLimitApplies(): void
    {
        $this->assertSame(
            'ok,ok,refused,refused,refused',
            $this->attempts([$this->rule(self::BY_ACCOUNT), $this->rule(self::BY_ADDRESS)])
        );
    }

    /**
     * The shape the docs used to show. Kept so the linter's warning stays true: if
     * `matchRule()` ever evaluates every matching entry, this fails, and the warning and
     * the docs need revisiting with it.
     */
    public function testAsOneRuleTheSecondEntryNeverRuns(): void
    {
        $this->assertSame(
            'ok,ok,ok,ok,ok',
            $this->attempts([$this->rule(self::BY_ACCOUNT, self::BY_ADDRESS)])
        );
    }

    /**
     * The runtime fact behind #437's warning: an earlier wildcard takes the request, and
     * the account limit written after it never applies.
     */
    public function testAnEarlierWildcardTakesTheRequest(): void
    {
        $this->assertSame(
            'ok,ok,ok,ok,ok',
            $this->attempts([$this->rule(['path' => '/log*', 'rate' => 50, 'sample' => 300], ['path' => '/login', 'rate' => 1, 'sample' => 300, 'key' => ['post.name']])])
        );
    }
}
