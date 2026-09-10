<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Event;

use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Tests\Event\ThrowingDispatcher;
use Kanopi\Firewall\Tests\Firewall\EvaluatingFirewall;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\HttpFoundation\Request;

/**
 * What the firewall announces, and to whom (#218).
 *
 * The buckets are mocked so each decision path can be reached on its own: the
 * question here is which event comes out of which branch, and building real
 * rules to provoke each branch would test the rules instead.
 */
class DecisionEventsTest extends AbstractTestCase
{
    private StorageInterface&MockObject $storage;

    private PluginManager&MockObject $blockManager;

    private PluginManager&MockObject $bypassManager;

    private PluginManager&MockObject $challengeManager;

    private RecordingDispatcher $dispatcher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->createMock(StorageInterface::class);
        $this->blockManager = $this->createMock(PluginManager::class);
        $this->bypassManager = $this->createMock(PluginManager::class);
        $this->challengeManager = $this->createMock(PluginManager::class);
        $this->dispatcher = new RecordingDispatcher();

        $this->storage->method('getKey')->willReturn('1.2.3.4');
        $this->storage->method('isBlocked')->willReturn(false);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function firewall(array $config = [], ?object $dispatcher = null): Firewall
    {
        return EvaluatingFirewall::make(
            $this->storage,
            $this->blockManager,
            $this->bypassManager,
            $this->challengeManager,
            $config,
            $dispatcher ?? $this->dispatcher
        );
    }

    private function plugin(string $name, int $status = 403): PluginInterface&MockObject
    {
        $plugin = $this->createMock(PluginInterface::class);
        $plugin->method('getName')->willReturn($name);
        $plugin->method('getStatusCode')->willReturn($status);
        $plugin->method('getExpirationTime')->willReturn(3600);

        return $plugin;
    }

    private function request(string $ip = '1.2.3.4'): Request
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'event-test');

        return $request;
    }

    private function quietBuckets(): void
    {
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn(false);
    }

    // -----------------------------------------------------------------------
    // Allowed
    // -----------------------------------------------------------------------

    /**
     * A request nothing objected to is still announced. A listener counting
     * traffic needs the denominator, and it is the only event most requests
     * will ever produce.
     */
    public function testAnUnremarkableRequestAnnouncesAnAllow(): void
    {
        $this->quietBuckets();

        $request = $this->request();
        $this->firewall()->evaluate($request);

        $this->assertSame(['RequestAllowed'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestAllowed::class, $event);
        $this->assertSame($request, $event->getRequest());
        $this->assertNull($event->getPlugin());
        $this->assertFalse($event->wasBypassed(), 'Nothing matched, so nothing bypassed it');
        $this->assertTrue($event->isEnforced());
    }

    /**
     * An allow rule matching is a different fact from nothing matching, and
     * an audit of who is skipping the firewall needs them apart.
     */
    public function testAnAllowRuleAnnouncesItselfAsTheBypass(): void
    {
        $plugin = $this->plugin('office-network');
        $this->bypassManager->method('evaluate')->willReturn($plugin);

        $this->firewall()->evaluate($this->request());

        $this->assertSame(['RequestAllowed'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestAllowed::class, $event);
        $this->assertSame($plugin, $event->getPlugin());
        $this->assertTrue($event->wasBypassed());
    }

    // -----------------------------------------------------------------------
    // Blocked
    // -----------------------------------------------------------------------

    /**
     * A rule block carries the rule and the status the client will get.
     */
    public function testARuleBlockAnnouncesTheRuleAndStatus(): void
    {
        $plugin = $this->plugin('bad-path', 418);
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);
        $this->storage->method('set')->willReturn(true);

        try {
            $this->firewall(['mode' => 'exception'])->evaluate($this->request());
            $this->fail('Expected the block to throw in exception mode.');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['RequestBlocked'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestBlocked::class, $event);
        $this->assertSame($plugin, $event->getPlugin());
        $this->assertSame(418, $event->getStatusCode());
        $this->assertTrue($event->isEnforced());
        $this->assertFalse($event->wasAlreadyBlocked());
    }

    /**
     * The event has to be dispatched before the response, because in every
     * mode but `exception` the response calls `exit()` -- announcing after it
     * would announce nothing at all. `exception` is the only mode a test can
     * observe, which is exactly why this ordering is worth asserting.
     */
    public function testTheBlockEventBeatsTheResponse(): void
    {
        $plugin = $this->plugin('bad-path');
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);
        $this->storage->method('set')->willReturn(true);

        $seen = [];
        $dispatcher = new RecordingDispatcher();

        try {
            $this->firewall(['mode' => 'exception'], $dispatcher)->evaluate($this->request());
        } catch (FirewallBlockedException) {
            $seen[] = 'exception';
        }

        $this->assertCount(1, $dispatcher->events, 'The event must survive the throw');
        $this->assertSame(['exception'], $seen);
    }

    /**
     * A client already on the durable block list has no rule to name, and
     * NULL is the honest answer -- the list records the key, not what put it
     * there.
     */
    public function testABlocklistHitAnnouncesNoRule(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('getKey')->willReturn('1.2.3.4');
        $storage->method('isBlocked')->willReturn(['event_id' => 'earlier-request']);
        $this->storage = $storage;

        $this->quietBuckets();

        try {
            $this->firewall(['mode' => 'exception', 'repeat_offender_status' => 429])
                ->evaluate($this->request());
            $this->fail('Expected the block list to throw in exception mode.');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['RequestBlocked'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestBlocked::class, $event);
        $this->assertNull($event->getPlugin());
        $this->assertTrue($event->wasAlreadyBlocked());
        $this->assertSame(429, $event->getStatusCode());
        $this->assertTrue($event->isEnforced());
    }

    // -----------------------------------------------------------------------
    // log mode
    // -----------------------------------------------------------------------

    /**
     * `mode: log` still announces, marked unenforced. A dry run is the
     * moment events are most useful -- it is the whole reason to be in that
     * mode -- and a listener that notifies somebody needs to be able to tell
     * that nothing actually happened.
     */
    public function testLogModeAnnouncesAnUnenforcedBlock(): void
    {
        $plugin = $this->plugin('bad-path', 403);
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);

        $this->assertTrue($this->firewall(['mode' => 'log'])->evaluate($this->request()));

        $this->assertSame(['RequestBlocked'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestBlocked::class, $event);
        $this->assertFalse($event->isEnforced());
        $this->assertSame($plugin, $event->getPlugin());
    }

    /**
     * A would-be block in `log` mode does not also announce an allow.
     *
     * It returns immediately, so the request is described once. Two events
     * would double every request in a listener counting outcomes.
     */
    public function testLogModeDoesNotAlsoAnnounceAnAllow(): void
    {
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($this->plugin('bad-path'));

        $this->firewall(['mode' => 'log'])->evaluate($this->request());

        $this->assertSame([], $this->dispatcher->ofType(RequestAllowed::class));
    }

    /**
     * The block list in `log` mode is the one place a single request really
     * does produce more than one event, because it is the one place nothing
     * returns.
     *
     * Documented rather than papered over: `log` terminates nothing, which is
     * what makes it a dry run, so a listed client gets an unenforced block
     * *and* the allow that follows it.
     */
    public function testLogModeBlocklistHitIsFollowedByTheAllowItDidNotStop(): void
    {
        $storage = $this->createMock(StorageInterface::class);
        $storage->method('getKey')->willReturn('1.2.3.4');
        $storage->method('isBlocked')->willReturn(['event_id' => 'earlier-request']);
        $this->storage = $storage;

        $this->quietBuckets();

        $this->assertTrue($this->firewall(['mode' => 'log'])->evaluate($this->request()));

        $this->assertSame(['RequestBlocked', 'RequestAllowed'], $this->dispatcher->names());

        $blocked = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestBlocked::class, $blocked);
        $this->assertFalse($blocked->isEnforced());
        $this->assertTrue($blocked->wasAlreadyBlocked());
    }

    /**
     * A would-be challenge in `log` mode reports the rule and the provider it
     * would have used, unenforced.
     *
     * Only reachable from a subclass that declines the CLI bypass, which is
     * why it lives here rather than in the integration suite that drives the
     * real challenge flow.
     */
    public function testLogModeAnnouncesAnUnenforcedChallenge(): void
    {
        $plugin = $this->plugin('suspicious-agent');
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn($plugin);
        $this->blockManager->method('evaluate')->willReturn(false);

        $this->assertTrue($this->firewall(['mode' => 'log'])->evaluate($this->request()));

        $this->assertSame(['RequestChallenged'], $this->dispatcher->names());

        $event = $this->dispatcher->events[0];
        $this->assertInstanceOf(RequestChallenged::class, $event);
        $this->assertFalse($event->isEnforced());
        $this->assertSame($plugin, $event->getPlugin());

        // No provider is configured on this bare firewall, so the name falls
        // back the same way `sendChallengeResponse()` would resolve it.
        $this->assertIsString($event->getProvider());
    }

    /**
     * `mode: disabled` evaluates nothing, so there is nothing to announce.
     */
    public function testDisabledModeAnnouncesNothing(): void
    {
        $this->bypassManager->expects($this->never())->method('evaluate');

        $this->assertTrue($this->firewall(['mode' => 'disabled'])->evaluate($this->request()));
        $this->assertSame([], $this->dispatcher->names());
    }

    // -----------------------------------------------------------------------
    // Failure containment
    // -----------------------------------------------------------------------

    /**
     * A listener that throws does not become the outage.
     *
     * The verdict is already decided when the event goes out, so a broken
     * listener must not be able to change it -- in either direction. Here the
     * block still throws, which is the direction that matters: a firewall that
     * stops blocking because somebody's StatsD box is down is worse than one
     * with no events at all.
     */
    public function testAThrowingListenerDoesNotStopTheBlock(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $plugin = $this->plugin('bad-path');
        $this->bypassManager->method('evaluate')->willReturn(false);
        $this->challengeManager->method('evaluate')->willReturn(false);
        $this->blockManager->method('evaluate')->willReturn($plugin);
        $this->storage->method('set')->willReturn(true);

        $dispatcher = new ThrowingDispatcher();

        $this->expectException(FirewallBlockedException::class);

        try {
            $this->firewall(['mode' => 'exception'], $dispatcher)->evaluate($this->request());
        } finally {
            $this->assertSame(1, $dispatcher->calls, 'The dispatcher was reached');
            $this->assertTrue(
                $handler->hasErrorThatContains('A decision listener threw, and was ignored'),
                'Swallowing it quietly would make a listener that has never run look like one that works'
            );
        }
    }

    /**
     * A throwing listener does not stop an ordinary request either, and the
     * log line names the event so the listener can be found.
     */
    public function testAThrowingListenerDoesNotStopAnAllowedRequest(): void
    {
        $handler = new TestHandler(Level::Debug);
        LoggingFactory::setLogger(new Logger('test', [$handler]));

        $this->quietBuckets();

        $dispatcher = new ThrowingDispatcher();

        $this->assertTrue($this->firewall([], $dispatcher)->evaluate($this->request()));

        $records = array_values(array_filter(
            $handler->getRecords(),
            static fn($record): bool => str_contains((string) $record->message, 'decision listener threw')
        ));

        $this->assertCount(1, $records);
        $this->assertSame(RequestAllowed::class, $records[0]->context['event']);
        $this->assertSame('the metrics socket is not there', $records[0]->context['listener_error']);
        $this->assertSame(\RuntimeException::class, $records[0]->context['listener_error_type']);
    }

    /**
     * No dispatcher is the default, and it costs a null check.
     */
    public function testNoDispatcherIsFine(): void
    {
        $this->quietBuckets();

        $firewall = EvaluatingFirewall::make(
            $this->storage,
            $this->blockManager,
            $this->bypassManager,
            $this->challengeManager,
        );

        $this->assertTrue($firewall->evaluate($this->request()));
    }

    /**
     * `Firewall::create()` takes the dispatcher as a trailing parameter, so
     * the ordinary entry point can register one without reaching for the
     * protected constructor.
     */
    public function testCreateAcceptsADispatcher(): void
    {
        $dispatcher = new RecordingDispatcher();

        $firewall = Firewall::create(
            [[
                'global' => ['mode' => 'exception'],
                'storage' => ['type' => 'Kanopi\\Firewall\\Storage\\InMemoryStorage'],
                'plugins' => [
                    [
                        'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                        'response' => 'block',
                        'enable' => true,
                        'config' => ['203.0.113.5'],
                    ],
                ],
            ]],
            [],
            $dispatcher
        );

        try {
            $firewall->evaluate($this->request('203.0.113.5'));
            $this->fail('Expected the rule to block.');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertSame(['RequestBlocked'], $dispatcher->names());

        $event = $dispatcher->events[0];
        $this->assertInstanceOf(RequestBlocked::class, $event);
        $this->assertSame('IP Address', $event->getPlugin()?->getName());
    }
}
