<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit;

use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Symfony\Component\HttpFoundation\Request;

/**
 * `mode: lockdown` — deny by default, with an allowlist (#304).
 *
 * The reason this is a mode rather than two ordinary rules is measurable, and
 * `testLockdownRecordsNobody()` is the test that measures it: a catch-all block rule
 * achieves the same refusal and writes **every legitimate visitor** to the durable block
 * list with escalation applied, so lifting it leaves a block list full of customers.
 */
class LockdownModeTest extends AbstractTestCase
{
    private RecordingDispatcher $dispatcher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dispatcher = new RecordingDispatcher();
    }

    /**
     * @param array<string, mixed> $global
     * @param array<int, array<string, mixed>> $plugins
     */
    private function firewall(array $global = [], array $plugins = []): Firewall
    {
        return Firewall::create(
            [[
                // `lockdown: true` with `mode: exception` — the combination a
                // framework host needs, and the one `mode: lockdown` cannot express.
                'global' => $global + ['mode' => 'exception', 'lockdown' => true, 'lockdown_allow' => ['198.51.100.0/24']],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
                'plugins' => $plugins,
            ]],
            [],
            $this->dispatcher
        );
    }

    private function request(string $ip): Request
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'lockdown-test');

        return $request;
    }

    private function isBlocked(Firewall $firewall, Request $request): bool
    {
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);

        return $storage->isBlocked($storage->getKey($request)) !== false;
    }

    /**
     * Everybody who is not on the list is refused.
     */
    public function testAVisitorNotOnTheListIsRefused(): void
    {
        try {
            $this->firewall()->evaluate($this->request('203.0.113.9'));
            $this->fail('Expected the lockdown to refuse the request.');
        } catch (FirewallLockdownException $e) {
            $this->assertSame(503, $e->getStatusCode());
            $this->assertSame(300, $e->getRetryAfter());
        }
    }

    /**
     * And the allowlist is served.
     */
    public function testAnAllowlistedVisitorIsServed(): void
    {
        $this->assertTrue($this->firewall()->evaluate($this->request('198.51.100.7')));
    }

    /**
     * **The point of the whole feature.** Refusing records nothing, so lifting
     * the lockdown restores the site rather than leaving a block list full of
     * the customers it refused.
     */
    public function testLockdownRecordsNobody(): void
    {
        $firewall = $this->firewall();

        foreach (['203.0.113.9', '203.0.113.10', '203.0.113.11'] as $ip) {
            try {
                $firewall->evaluate($this->request($ip));
            } catch (FirewallLockdownException) {
                // expected
            }
        }

        foreach (['203.0.113.9', '203.0.113.10', '203.0.113.11'] as $ip) {
            $this->assertFalse(
                $this->isBlocked($firewall, $this->request($ip)),
                sprintf('%s was recorded. Lifting the lockdown would leave them banned.', $ip)
            );
        }
    }

    /**
     * A host catching the existing exception keeps working.
     */
    public function testItExtendsTheBlockedExceptionSoHostsKeepWorking(): void
    {
        $this->expectException(FirewallBlockedException::class);
        $this->firewall()->evaluate($this->request('203.0.113.9'));
    }

    /**
     * An empty allowlist serves nobody — which is what deny-by-default means,
     * and why `firewall-doctor` reports it before you rely on it.
     */
    public function testAnEmptyAllowlistServesNobody(): void
    {
        $this->expectException(FirewallLockdownException::class);
        $this->firewall(['lockdown_allow' => []])->evaluate($this->request('198.51.100.7'));
    }

    /**
     * An allow *rule* does not grant entry. Only `lockdown_allow` does.
     *
     * Question 1 of the issue: an allow rule written months ago to whitelist a payment
     * webhook is not a considered answer to "who should reach this site while it is under
     * attack".
     */
    public function testAnAllowRuleDoesNotGrantEntry(): void
    {
        $firewall = $this->firewall([], [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'allow',
            'weight' => -999,
            'enable' => true,
            'metadata' => ['name' => 'payment-webhook'],
            'config' => ['203.0.113.9'],
        ]]);

        $this->expectException(FirewallLockdownException::class);
        $firewall->evaluate($this->request('203.0.113.9'));
    }

    /**
     * A client on the allowlist still faces everything below — lockdown adds a
     * refusal, it never removes one. Question 3 of the issue.
     */
    public function testTheAllowlistDoesNotBypassTheRules(): void
    {
        $firewall = $this->firewall([], [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'still-banned'],
            'config' => ['198.51.100.7'],
        ]]);

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($this->request('198.51.100.7'));
    }

    /**
     * The durable block list still applies to an allowlisted client, which is
     * the other half of question 3.
     */
    public function testTheBlockListStillAppliesToAnAllowlistedClient(): void
    {
        $firewall = $this->firewall();
        $victim = $this->request('198.51.100.7');

        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);
        $storage->set($storage->getKey($victim), ['event_id' => 'earlier'], time() + 3600);

        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($victim);
    }

    /**
     * The status and Retry-After are configurable, because a lockdown that
     * lasts an hour and one that lasts a minute are different messages.
     */
    public function testTheStatusAndRetryAfterAreConfigurable(): void
    {
        try {
            $this->firewall(['lockdown_status' => 429, 'lockdown_retry_after' => 30])
                ->evaluate($this->request('203.0.113.9'));
            $this->fail('Expected refusal.');
        } catch (FirewallLockdownException $e) {
            $this->assertSame(429, $e->getStatusCode());
            $this->assertSame(30, $e->getRetryAfter());
        }
    }

    /**
     * A negative Retry-After is clamped rather than emitted.
     */
    public function testANegativeRetryAfterIsClamped(): void
    {
        try {
            $this->firewall(['lockdown_retry_after' => -5])->evaluate($this->request('203.0.113.9'));
            $this->fail('Expected refusal.');
        } catch (FirewallLockdownException $e) {
            $this->assertSame(0, $e->getRetryAfter());
        }
    }

    /**
     * It announces itself as an enforced block with no rule behind it.
     */
    public function testTheRefusalIsAnnounced(): void
    {
        try {
            $this->firewall()->evaluate($this->request('203.0.113.9'));
        } catch (FirewallLockdownException) {
            // expected
        }

        $events = $this->dispatcher->ofType(\Kanopi\Firewall\Event\RequestBlocked::class);

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\Kanopi\Firewall\Event\RequestBlocked::class, $events[0]);
        $this->assertNull($events[0]->getPlugin(), 'No rule refused this — the mode did.');
        $this->assertTrue($events[0]->isEnforced());
        $this->assertSame(503, $events[0]->getStatusCode());
    }

    /**
     * `mode: lockdown` is shorthand, and it is a *delivery* downgrade.
     *
     * It means "lock down, and refuse the way `block` refuses". A host that needs exception
     * delivery must use `lockdown: true` and keep its own mode — which is the whole reason
     * lockdown is a flag and not a mode.
     */
    public function testModeLockdownIsShorthandForLockdownPlusBlockDelivery(): void
    {
        $firewall = Firewall::create([[
            'global' => ['mode' => 'lockdown', 'lockdown_allow' => ['198.51.100.0/24']],
            'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
        ]]);

        $this->assertTrue($firewall->isLockedDown());
        $this->assertSame(
            \Kanopi\Firewall\FirewallMode::Block,
            $firewall->getMode(),
            'The delivery mode falls back to block, because lockdown does not describe delivery.'
        );
    }

    /**
     * A panic file saying `lockdown` does the same, without a deploy.
     */
    public function testThePanicFileCanEnterLockdown(): void
    {
        $panic = sys_get_temp_dir() . '/fw-lockdown-panic-' . uniqid();
        file_put_contents($panic, 'lockdown');

        try {
            $firewall = Firewall::create([[
                'global' => [
                    'mode' => 'block',
                    'panic_file' => $panic,
                    'lockdown_allow' => ['198.51.100.0/24'],
                ],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            ]]);

            $this->assertTrue($firewall->isLockedDown(), 'The panic file should have entered lockdown.');
        } finally {
            @unlink($panic);
        }
    }

    /**
     * `lockdown: true` leaves the mode alone, which is the point.
     */
    public function testTheFlagLeavesTheDeliveryModeAlone(): void
    {
        $firewall = $this->firewall();

        $this->assertTrue($firewall->isLockedDown());
        $this->assertSame(\Kanopi\Firewall\FirewallMode::Exception, $firewall->getMode());
    }

    /**
     * IPv6 works, since an allowlist that silently covered only IPv4 would
     * lock out half the people it named.
     */
    public function testIpv6IsMatched(): void
    {
        $firewall = $this->firewall(['lockdown_allow' => ['2001:db8::/32']]);

        $this->assertTrue($firewall->evaluate($this->request('2001:db8::1')));

        $this->expectException(FirewallLockdownException::class);
        $firewall->evaluate($this->request('2001:db9::1'));
    }

    /**
     * `mode: log` reports the lockdown and serves the request, the same way it
     * treats every other terminal decision.
     */
    public function testLogModeReportsWithoutRefusing(): void
    {
        $firewall = Firewall::create(
            [[
                'global' => ['mode' => 'log', 'lockdown' => true, 'lockdown_allow' => ['198.51.100.0/24']],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
            ]],
            [],
            $this->dispatcher
        );

        // `log` short-circuits under the CLI SAPI, so drive the refusal
        // directly rather than asserting on an early return.
        (new \ReflectionMethod($firewall, 'sendLockdownResponse'))
            ->invoke($firewall, $this->request('203.0.113.9'));

        $events = $this->dispatcher->ofType(\Kanopi\Firewall\Event\RequestBlocked::class);

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\Kanopi\Firewall\Event\RequestBlocked::class, $events[0]);
        $this->assertFalse($events[0]->isEnforced(), 'Nothing was actually refused.');
    }

    /**
     * A request with no resolvable client IP is refused rather than waved
     * through. Deny by default means deny the ones you cannot identify.
     */
    public function testARequestWithNoClientIpIsRefused(): void
    {
        $firewall = $this->firewall();

        $request = Request::create('/', 'GET');
        $request->server->remove('REMOTE_ADDR');
        $request->attributes->set('x-request-id', 'no-ip');

        $this->expectException(FirewallLockdownException::class);
        $firewall->evaluate($request);
    }

    /**
     * A custom message reaches the visitor, interpolated.
     */
    public function testTheMessageIsConfigurableAndInterpolated(): void
    {
        try {
            $this->firewall(['lockdown_message' => 'Closed — ref {{request.id}}'])
                ->evaluate($this->request('203.0.113.9'));
            $this->fail('Expected refusal.');
        } catch (FirewallLockdownException $e) {
            $this->assertStringContainsString('Closed —', $e->getMessage());
            $this->assertStringNotContainsString('{{request.id}}', $e->getMessage());
        }
    }

    /**
     * A non-list `lockdown_allow` serves nobody rather than erroring.
     */
    public function testANonListAllowlistServesNobody(): void
    {
        $this->expectException(FirewallLockdownException::class);
        $this->firewall(['lockdown_allow' => 'not-a-list'])->evaluate($this->request('198.51.100.7'));
    }

    /**
     * A malformed entry is skipped rather than matching everything or nothing
     * unpredictably.
     */
    public function testMalformedAllowlistEntriesAreSkipped(): void
    {
        $firewall = $this->firewall(['lockdown_allow' => ['', '   ', 198, null, '198.51.100.0/24']]);

        $this->assertTrue($firewall->evaluate($this->request('198.51.100.7')));
    }
}
