<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Event;

use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * `response: mark` — the firewall as a signal source rather than a gate (#203).
 *
 * The action the issue calls the interesting one, and it is: a comment form can show a
 * CAPTCHA to requests the firewall found suspicious instead of to everybody, and the
 * decision stays with the code that knows what the request was trying to do.
 */
class MarkResponseTest extends AbstractTestCase
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
    private function firewall(array $plugins): Firewall
    {
        return Firewall::create(
            [[
                'global' => ['mode' => 'exception'],
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
    private function markRule(array $metadata = []): array
    {
        return [[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'mark',
            'enable' => true,
            'metadata' => $metadata + ['name' => 'suspicious'],
            'config' => ['203.0.113.0/24'],
        ]];
    }

    private function request(string $ip = '203.0.113.9'): Request
    {
        $request = Request::create('/comment', 'POST', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'mark-test');

        return $request;
    }

    /**
     * The request goes through, carrying a signal.
     */
    public function testAMarkedRequestIsServedAndAnnotated(): void
    {
        $request = $this->request();

        $this->assertTrue($this->firewall($this->markRule())->evaluate($request));

        $this->assertTrue($request->attributes->get('firewall.mark.suspicious'));
        $this->assertSame(['suspicious'], $request->attributes->get('firewall.marks'));
    }

    /**
     * An application can ask "was this marked at all" without knowing which
     * rules exist.
     */
    public function testTheMarksListIsUsableWithoutKnowingTheRules(): void
    {
        $request = $this->request();
        $this->firewall($this->markRule(['mark_as' => 'needs-captcha']))->evaluate($request);

        $this->assertNotSame([], $request->attributes->get('firewall.marks'));
        $this->assertSame(['needs-captcha'], $request->attributes->get('firewall.marks'));
        $this->assertTrue($request->attributes->get('firewall.mark.needs-captcha'));
    }

    /**
     * Several rules can raise one shared signal.
     */
    public function testSeveralRulesCanRaiseOneSignal(): void
    {
        $request = $this->request();

        $this->firewall([
            [
                'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                'response' => 'mark',
                'weight' => 0,
                'enable' => true,
                'metadata' => ['name' => 'bad-range', 'mark_as' => 'needs-captcha'],
                'config' => ['203.0.113.0/24'],
            ],
        ])->evaluate($request);

        $this->assertSame(['needs-captcha'], $request->attributes->get('firewall.marks'));
    }

    /**
     * An unmatched rule leaves the request untouched — no empty list, no flag.
     */
    public function testAnUnmatchedMarkRuleAnnotatesNothing(): void
    {
        $request = $this->request('198.51.100.7');

        $this->assertTrue($this->firewall($this->markRule())->evaluate($request));
        $this->assertNull($request->attributes->get('firewall.marks'));
        $this->assertNull($request->attributes->get('firewall.mark.suspicious'));
    }

    /**
     * A header too, when asked for, since not every host reads HttpFoundation
     * attributes.
     */
    public function testAHeaderCanBeSetAsWell(): void
    {
        $request = $this->request();
        $this->firewall($this->markRule(['mark_header' => 'X-Firewall-Mark']))->evaluate($request);

        $this->assertSame('suspicious', $request->headers->get('X-Firewall-Mark'));
    }

    /**
     * And not otherwise. A firewall that silently adds headers to every marked
     * request surprises whatever reads them next.
     */
    public function testNoHeaderUnlessAsked(): void
    {
        $request = $this->request();
        $this->firewall($this->markRule())->evaluate($request);

        $this->assertNull($request->headers->get('X-Firewall-Mark'));
    }

    /**
     * The event is the channel that always arrives.
     *
     * The attribute only reaches code holding this same Request instance — a
     * `settings.php` bootstrap that later builds its own does not see it.
     */
    public function testTheMarkIsAnnounced(): void
    {
        $this->firewall($this->markRule())->evaluate($this->request());

        $events = $this->dispatcher->ofType(RequestMarked::class);

        $this->assertCount(1, $events);
        $this->assertInstanceOf(RequestMarked::class, $events[0]);
        $this->assertSame('suspicious', $events[0]->getMark());
        $this->assertSame('firewall.mark.suspicious', $events[0]->getAttribute());
        $this->assertSame('suspicious', $events[0]->getPlugin()->getName());
        $this->assertFalse($events[0]->isEnforced(), 'Marking is the action; nothing was enforced.');
    }

    /**
     * A marked request that is *also* blocked is still marked.
     *
     * Marking runs before anything terminal, deliberately: a mark that only appeared on
     * requests nobody refused would be a signal you could not correlate with anything.
     */
    public function testAMarkSurvivesARequestThatIsAlsoBlocked(): void
    {
        $request = $this->request();

        $rules = $this->markRule();
        $rules[] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'blocker'],
            'config' => ['203.0.113.0/24'],
        ];

        try {
            $this->firewall($rules)->evaluate($request);
            $this->fail('Expected the block rule to refuse the request.');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertTrue($request->attributes->get('firewall.mark.suspicious'));
        $this->assertCount(1, $this->dispatcher->ofType(RequestMarked::class));
    }

    /**
     * An allow rule still wins, so a client you trust is not marked either.
     */
    public function testAnAllowRuleBeatsAMarkRule(): void
    {
        $request = $this->request();

        $rules = $this->markRule();
        $rules[] = [
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'allow',
            'weight' => -100,
            'enable' => true,
            'metadata' => ['name' => 'trusted'],
            'config' => ['203.0.113.9'],
        ];

        $this->assertTrue($this->firewall($rules)->evaluate($request));
        $this->assertNull($request->attributes->get('firewall.marks'));
    }

    /**
     * Marking writes nothing to the block list. It is the corner of the grid
     * where neither refusing nor recording happens.
     */
    public function testMarkingRecordsNothing(): void
    {
        $firewall = $this->firewall($this->markRule());
        $request = $this->request();

        $firewall->evaluate($request);

        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);

        $this->assertFalse($storage->isBlocked($storage->getKey($request)));
    }
}
