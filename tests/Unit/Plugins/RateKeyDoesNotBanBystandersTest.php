<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Plugins;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A limit that counts something other than the address must not ban an address (#200).
 *
 * The durable block list is keyed on the client IP — `AbstractStorageBase::getKey()` returns
 * it and nothing overrides that. Counting by `post.name` and then banning on trip therefore
 * punishes whichever address happens to make the request that crosses the line, which is not
 * necessarily one that spent any of the budget.
 *
 * The attack that follows is the reason this is a default and not a documentation note: an
 * attacker exhausts a victim's account budget from their own machines, the victim's next
 * login trips the limit, and **the victim's address is written to the durable block list**
 * — where it is refused for everything, not just that account, with `blocking_escalation`
 * lengthening the ban each time it happens.
 *
 * Remote, unauthenticated, against arbitrary users.
 */
class RateKeyDoesNotBanBystandersTest extends AbstractTestCase
{
    /**
     * @param array<int, string> $key
     * @param array<string, mixed> $metadata
     */
    private function firewall(array $key, array $metadata = []): Firewall
    {
        return Firewall::create([[
            'global' => ['mode' => 'exception'],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            'plugins' => [[
                'plugin' => 'Kanopi\\Firewall\\Plugins\\RateLimit',
                'response' => 'block',
                'enable' => true,
                'metadata' => $metadata + [
                    'name' => 'login-limit',
                    'limit_unlisted_paths' => false,
                    'storage' => [
                        'type' => 'Kanopi\\Firewall\\RateLimitStorage\\InMemoryRateLimitStorage',
                        'config' => [],
                    ],
                ],
                'config' => [['path' => '/login', 'rate' => 3, 'sample' => 300, 'key' => $key]],
            ]],
        ]]);
    }

    private function attempt(Firewall $firewall, string $ip, string $name = 'victim'): bool
    {
        $request = Request::create('/login', 'POST', ['name' => $name], [], [], ['REMOTE_ADDR' => $ip]);

        try {
            $firewall->evaluate($request);

            return true;
        } catch (FirewallBlockedException) {
            return false;
        }
    }

    private function isBanned(Firewall $firewall, string $ip): bool
    {
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);

        return $storage->isBlocked($storage->getKey($request)) !== false;
    }

    /**
     * The attack, and that it no longer lands.
     */
    public function testExhaustingAnAccountDoesNotBanItsOwner(): void
    {
        $firewall = $this->firewall(['post.name']);

        // The attacker spends the account's budget from machines of their own.
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'] as $ip) {
            $this->attempt($firewall, $ip);
        }

        // The real owner of the account now tries to log in.
        $this->assertFalse(
            $this->attempt($firewall, '198.51.100.7'),
            'The account budget is spent, so this attempt is refused — that much is inherent.'
        );

        $this->assertFalse(
            $this->isBanned($firewall, '198.51.100.7'),
            'But their address must not be on the durable block list. An attacker could '
            . 'otherwise get any user banned by attacking their username.'
        );
    }

    /**
     * And the rest of their traffic is untouched, which is what a durable IP
     * ban would have taken from them.
     */
    public function testTheirOtherTrafficIsUnaffected(): void
    {
        $firewall = $this->firewall(['post.name']);

        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'] as $ip) {
            $this->attempt($firewall, $ip);
        }

        $this->attempt($firewall, '198.51.100.7');

        $this->assertTrue(
            $this->attempt($firewall, '198.51.100.7', 'a-different-account'),
            'A durable ban is address-wide, so it would have refused everything they do.'
        );
    }

    /**
     * An account key gives every account its own budget.
     *
     * Which is the point, and also the limitation: one address working through a username
     * list gets a fresh budget per name and is never limited by that rule — nor banned,
     * since a non-address key does not record. An account key and an address key catch
     * opposite attacks, and swapping one for the other removes protection while looking
     * like it adds it.
     *
     * Pinned as a test because it is the behaviour somebody will reason their way to the
     * wrong answer about, and `firewall-check --lint` now warns about the configuration
     * that produces it.
     */
    public function testAnAccountKeyDoesNotLimitOneAddressAcrossManyAccounts(): void
    {
        $firewall = $this->firewall(['post.name']);

        // Spend one account's budget entirely.
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'] as $ip) {
            $this->attempt($firewall, $ip);
        }

        // The same address now tries other accounts, and each is a fresh bucket.
        foreach (['alice', 'bob', 'carol', 'dave'] as $name) {
            $this->assertTrue(
                $this->attempt($firewall, '10.0.0.3', $name),
                sprintf('An account key does not limit one address across accounts; %s should pass.', $name)
            );
        }

        $this->assertFalse($this->isBanned($firewall, '10.0.0.3'));
    }

    /**
     * A limit counting by address still bans, because there the address really
     * did spend the budget.
     */
    public function testCountingByAddressStillBans(): void
    {
        $firewall = $this->firewall(['client_ip', 'rule_pattern']);

        foreach (range(1, 4) as $ignored) {
            $this->attempt($firewall, '203.0.113.9');
        }

        $this->assertTrue(
            $this->isBanned($firewall, '203.0.113.9'),
            'Unchanged behaviour for every rule that does not opt into a different identity.'
        );
    }

    /**
     * A key that includes the address alongside something else still bans, for
     * the same reason.
     */
    public function testAKeyThatIncludesTheAddressStillBans(): void
    {
        $firewall = $this->firewall(['client_ip', 'post.name']);

        foreach (range(1, 4) as $ignored) {
            $this->attempt($firewall, '203.0.113.9');
        }

        $this->assertTrue($this->isBanned($firewall, '203.0.113.9'));
    }

    /**
     * An operator who knows the counted identity and the address are the same
     * thing can opt back in.
     */
    public function testRecordTrueOptsBackIn(): void
    {
        $firewall = $this->firewall(['post.name'], ['record' => true]);

        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'] as $ip) {
            $this->attempt($firewall, $ip);
        }

        $this->attempt($firewall, '198.51.100.7');

        $this->assertTrue($this->isBanned($firewall, '198.51.100.7'));
    }

    /**
     * And `record: false` still suppresses the ban even when counting by
     * address, since an explicit answer wins either way.
     */
    public function testRecordFalseWinsOverAnAddressKey(): void
    {
        $firewall = $this->firewall(['client_ip', 'rule_pattern'], ['record' => false]);

        foreach (range(1, 4) as $ignored) {
            $this->attempt($firewall, '203.0.113.9');
        }

        $this->assertFalse($this->isBanned($firewall, '203.0.113.9'));
    }
}
