<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Event;

use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * `response: redirect` — sending a visitor somewhere instead of refusing them (#203).
 *
 * The gentle end of a terminal decision. A block tells a visitor nothing and leaves them
 * nowhere to go, which is right for a scanner and poor for the false positive who is now
 * looking at an unexplained error on a site they were trying to buy something from.
 */
class RedirectResponseTest extends AbstractTestCase
{
    private RecordingDispatcher $dispatcher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dispatcher = new RecordingDispatcher();
    }

    /**
     * @param array<int, array<string, mixed>> $plugins
     */
    private function firewall(array $plugins, string $mode = 'exception'): Firewall
    {
        return Firewall::create(
            [[
                'global' => ['mode' => $mode],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
                'plugins' => $plugins,
            ]],
            [],
            $this->dispatcher
        );
    }

    /**
     * @param array<string, mixed> $metadata
     *
     * @return array<int, array<string, mixed>>
     */
    private function redirectRule(array $metadata = []): array
    {
        return [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'redirect',
            'enable' => true,
            'metadata' => $metadata + ['name' => 'wrongly-caught', 'redirect_to' => '/why-am-i-here'],
            'config' => ['203.0.113.0/24'],
        ]];
    }

    private function request(string $ip = '203.0.113.9'): Request
    {
        $request = Request::create('/checkout', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'redirect-test');

        return $request;
    }

    private function isBlocked(Firewall $firewall, Request $request): bool
    {
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);

        return $storage->isBlocked($storage->getKey($request)) !== false;
    }

    public function testAMatchingRuleRedirects(): void
    {
        $firewall = $this->firewall($this->redirectRule());

        try {
            $firewall->evaluate($this->request());
            $this->fail('Expected FirewallRedirectException.');
        } catch (FirewallRedirectException $e) {
            $this->assertSame('/why-am-i-here', $e->getLocation());
            $this->assertSame(302, $e->getStatusCode());
        }
    }

    /**
     * 302 by default, and only the four real redirect statuses are honoured.
     *
     * A 301 is cached by browsers and intermediaries more or less forever, and a rule's
     * verdict changes with the next configuration edit — somebody caught by a rule that is
     * later tuned should not keep being sent to the notice page.
     *
     * @param mixed $configured
     *   What `metadata.redirect_status` held.
     */
    #[DataProvider('redirectStatuses')]
    public function testTheRedirectStatus(mixed $configured, int $expected): void
    {
        $firewall = $this->firewall($this->redirectRule(['redirect_status' => $configured]));

        try {
            $firewall->evaluate($this->request());
            $this->fail('Expected FirewallRedirectException.');
        } catch (FirewallRedirectException $e) {
            $this->assertSame($expected, $e->getStatusCode());
        }
    }

    /**
     * @return array<string, array{mixed, int}>
     */
    public static function redirectStatuses(): array
    {
        return [
            'unset' => [null, 302],
            '301' => [301, 301],
            '307' => [307, 307],
            '308' => [308, 308],
            'a status that is not a redirect' => [404, 302],
            'a string' => ['301', 302],
            'nonsense' => ['soon', 302],
        ];
    }

    /**
     * A redirect rule with nowhere to send them is a misconfiguration, said out loud.
     *
     * Falling through to the block bucket would refuse a visitor the operator meant to send
     * somewhere, and serving a redirect to nowhere is worse than either.
     */
    public function testARuleWithNoDestinationIsRefusedLoudly(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'redirect',
            'enable' => true,
            'metadata' => ['name' => 'nowhere'],
            'config' => ['203.0.113.0/24'],
        ]]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessageMatches('/names no metadata.redirect_to/');

        $firewall->evaluate($this->request());
    }

    /**
     * A redirect records nothing by default.
     *
     * It is a signpost, not a ban. A visitor sent to a notice page who came back to find
     * themselves blocked instead would have no way to understand why.
     */
    public function testARedirectRecordsNothingByDefault(): void
    {
        $firewall = $this->firewall($this->redirectRule());
        $request = $this->request();

        try {
            $firewall->evaluate($request);
        } catch (FirewallRedirectException) {
            // expected
        }

        $this->assertFalse($this->isBlocked($firewall, $request));
    }

    /**
     * And records when explicitly asked to — the opposite default from a block,
     * which records unless told not to.
     */
    public function testARedirectCanOptIntoRecording(): void
    {
        $firewall = $this->firewall($this->redirectRule(['record' => true]));
        $request = $this->request();

        try {
            $firewall->evaluate($request);
        } catch (FirewallRedirectException) {
            // expected
        }

        $this->assertTrue($this->isBlocked($firewall, $request));
    }

    /**
     * Terminal buckets run gentlest first, so a redirect beats a block.
     */
    public function testARedirectRuleBeatsABlockRule(): void
    {
        $firewall = $this->firewall([
            $this->redirectRule()[0],
            [
                'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                'response' => 'block',
                'weight' => -999,
                'enable' => true,
                'metadata' => ['name' => 'hard-block'],
                'config' => ['203.0.113.0/24'],
            ],
        ]);

        $this->expectException(FirewallRedirectException::class);
        $firewall->evaluate($this->request());
    }

    /**
     * An allow rule still wins over everything.
     */
    public function testAnAllowRuleBeatsARedirectRule(): void
    {
        $rules = $this->redirectRule();
        $rules[] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'allow',
            'weight' => 999,
            'enable' => true,
            'metadata' => ['name' => 'trusted'],
            'config' => ['203.0.113.9'],
        ];

        $this->assertTrue($this->firewall($rules)->evaluate($this->request()));
    }

    public function testTheRedirectIsAnnounced(): void
    {
        $firewall = $this->firewall($this->redirectRule());

        try {
            $firewall->evaluate($this->request());
        } catch (FirewallRedirectException) {
            // expected
        }

        $events = $this->dispatcher->ofType(RequestRedirected::class);

        $this->assertCount(1, $events);
        $this->assertInstanceOf(RequestRedirected::class, $events[0]);
        $this->assertSame('/why-am-i-here', $events[0]->getLocation());
        $this->assertSame(302, $events[0]->getStatusCode());
        $this->assertSame('wrongly-caught', $events[0]->getPlugin()->getName());
        $this->assertTrue($events[0]->isEnforced());
    }

    /**
     * `mode: log` reports the redirect and lets the request through, the same
     * way it treats every other terminal decision.
     */
    public function testLogModeReportsWithoutRedirecting(): void
    {
        $firewall = $this->firewall($this->redirectRule(), 'log');

        // `log` short-circuits under the CLI SAPI, so drive the method directly
        // rather than asserting on an early return that proves nothing.
        $method = new \ReflectionMethod($firewall, 'sendRedirectResponse');
        $plugins = (new \ReflectionProperty($firewall, 'redirectPluginManager'))->getValue($firewall)->getPlugins();

        $method->invoke($firewall, $this->request(), reset($plugins));

        $events = $this->dispatcher->ofType(RequestRedirected::class);

        $this->assertCount(1, $events);
        $this->assertInstanceOf(RequestRedirected::class, $events[0]);
        $this->assertFalse($events[0]->isEnforced(), 'Nothing was actually redirected.');
    }

    /**
     * An unmatched redirect rule leaves the request alone.
     */
    public function testAnUnmatchedRedirectRuleDoesNothing(): void
    {
        $this->assertTrue($this->firewall($this->redirectRule())->evaluate($this->request('198.51.100.7')));
        $this->assertSame([], $this->dispatcher->ofType(RequestRedirected::class));
    }

    /**
     * A block rule still blocks when no redirect rule matches.
     */
    public function testABlockRuleStillBlocks(): void
    {
        $rules = $this->redirectRule();
        $rules[0]['config'] = ['198.51.100.0/24'];
        $rules[] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'hard-block'],
            'config' => ['203.0.113.0/24'],
        ];

        $this->expectException(FirewallBlockedException::class);
        $this->firewall($rules)->evaluate($this->request());
    }
}
