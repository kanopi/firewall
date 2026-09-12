<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Event;

use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestRecorded;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Tests\Event\RecordingDispatcher;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Refusing and recording, taken apart (#203).
 *
 * They have been one action since the firewall shipped: a block writes the client to the
 * durable list, and there was no way to have either without the other. That is fine for an
 * ordinary rule and wrong at both ends of the range —
 *
 * - a **honeypot** wants the client recorded and this request served normally, because
 *   refusing it tells the scanner exactly which URL is wired (#202);
 * - a **lockdown** wants everybody refused and nobody recorded, because a deliberate
 *   temporary refusal is not evidence anybody misbehaved, and recording leaves a block list
 *   full of customers once it is lifted (#304).
 *
 * Driven through `Firewall::create()` and a real storage backend rather than mocks: the
 * question is what ends up in the block list, and a mocked store would test the mock.
 */
class RecordAndRefuseTest extends AbstractTestCase
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

    private function request(string $ip = '203.0.113.9', string $path = '/'): Request
    {
        $request = Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip]);
        $request->attributes->set('x-request-id', 'record-test');

        return $request;
    }

    private function isBlocked(Firewall $firewall, Request $request): bool
    {
        $storage = (new \ReflectionProperty($firewall, 'storage'))->getValue($firewall);

        return $storage->isBlocked($storage->getKey($request)) !== false;
    }

    // -----------------------------------------------------------------------
    // record without refusing
    // -----------------------------------------------------------------------

    /**
     * `response: record` serves the request and blocks the *next* one.
     *
     * The whole point for a honeypot: a scanner that fetches the wired URL gets an
     * ordinary response and learns nothing, and is refused when it comes back.
     */
    public function testRecordServesThisRequestAndBlocksTheNext(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
            'response' => 'record',
            'enable' => true,
            'metadata' => ['name' => 'honeypot'],
            'config' => ['path:/wp-admin.bak'],
        ]]);

        $trap = $this->request(path: '/wp-admin.bak');

        $this->assertTrue($firewall->evaluate($trap), 'The request that sprang the trap must be served normally.');
        $this->assertTrue($this->isBlocked($firewall, $trap), 'The client should now be on the block list.');

        // Anything from that client now, including an innocent URL.
        $this->expectException(FirewallBlockedException::class);
        $firewall->evaluate($this->request(path: '/'));
    }

    /**
     * It announces itself, because nothing else about the request does.
     */
    public function testRecordIsAnnouncedAsAnUnenforcedDecision(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
            'response' => 'record',
            'enable' => true,
            'metadata' => ['name' => 'honeypot'],
            'config' => ['path:/wp-admin.bak'],
        ]]);

        $firewall->evaluate($this->request(path: '/wp-admin.bak'));

        $recorded = $this->dispatcher->ofType(RequestRecorded::class);

        $this->assertCount(1, $recorded);
        $this->assertInstanceOf(RequestRecorded::class, $recorded[0]);
        $this->assertSame('honeypot', $recorded[0]->getPlugin()->getName());
        $this->assertTrue($recorded[0]->wasStored());
        $this->assertFalse($recorded[0]->isEnforced(), 'Nothing was refused.');
    }

    /**
     * A record rule does not match, so nothing is recorded and nothing announced.
     */
    public function testAnUnmatchedRecordRuleDoesNothing(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
            'response' => 'record',
            'enable' => true,
            'metadata' => ['name' => 'honeypot'],
            'config' => ['path:/wp-admin.bak'],
        ]]);

        $ordinary = $this->request(path: '/about');

        $this->assertTrue($firewall->evaluate($ordinary));
        $this->assertFalse($this->isBlocked($firewall, $ordinary));
        $this->assertSame([], $this->dispatcher->ofType(RequestRecorded::class));
    }

    /**
     * An allow rule still wins. The allow bucket runs first, so a client you
     * trust does not spring a trap.
     */
    public function testAnAllowRuleBeatsARecordRule(): void
    {
        $firewall = $this->firewall([
            [
                'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
                'response' => 'allow',
                'weight' => -100,
                'enable' => true,
                'metadata' => ['name' => 'office'],
                'config' => ['198.51.100.0/24'],
            ],
            [
                'plugin' => 'Kanopi\\Firewall\\Plugins\\Url',
                'response' => 'record',
                'enable' => true,
                'metadata' => ['name' => 'honeypot'],
                'config' => ['path:/wp-admin.bak'],
            ],
        ]);

        $trusted = $this->request('198.51.100.7', '/wp-admin.bak');

        $this->assertTrue($firewall->evaluate($trusted));
        $this->assertFalse($this->isBlocked($firewall, $trusted), 'An allowed client must not be recorded.');
    }

    // -----------------------------------------------------------------------
    // refuse without recording
    // -----------------------------------------------------------------------

    /**
     * `metadata.record: false` refuses and writes nothing.
     *
     * What a lockdown needs. Every visitor refused during one is refused deliberately and
     * temporarily; recording them means lifting the lockdown leaves a block list full of
     * customers, each on an escalating ban.
     */
    public function testRecordFalseRefusesWithoutRecording(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'lockdown', 'record' => false],
            'config' => ['0.0.0.0/0', '::/0'],
        ]]);

        $visitor = $this->request();

        try {
            $firewall->evaluate($visitor);
            $this->fail('Expected the rule to refuse the request.');
        } catch (FirewallBlockedException) {
            $this->addToAssertionCount(1);
        }

        $this->assertFalse(
            $this->isBlocked($firewall, $visitor),
            'A refusal with record: false must leave nothing behind — that is the whole point.'
        );
    }

    /**
     * And it still announces the block, because the visitor was refused.
     */
    public function testAnUnrecordedBlockIsStillAnnouncedAsEnforced(): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => ['name' => 'lockdown', 'record' => false],
            'config' => ['0.0.0.0/0'],
        ]]);

        try {
            $firewall->evaluate($this->request());
        } catch (FirewallBlockedException) {
            // expected
        }

        $blocked = $this->dispatcher->ofType(RequestBlocked::class);

        $this->assertCount(1, $blocked);
        $this->assertInstanceOf(RequestBlocked::class, $blocked[0]);
        $this->assertTrue($blocked[0]->isEnforced(), 'The visitor really was refused.');
    }

    /**
     * Recording is the default, so every rule written before 2.26.0 is unchanged.
     *
     * @param array<string, mixed> $metadata
     *   What the rule declares.
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('recordingMetadata')]
    public function testRecordingIsTheDefault(array $metadata, bool $expectRecorded): void
    {
        $firewall = $this->firewall([[
            'plugin' => 'Kanopi\\Firewall\\Plugins\\IpAddress',
            'response' => 'block',
            'enable' => true,
            'metadata' => $metadata + ['name' => 'blocker'],
            'config' => ['0.0.0.0/0'],
        ]]);

        $visitor = $this->request();

        try {
            $firewall->evaluate($visitor);
        } catch (FirewallBlockedException) {
            // expected
        }

        $this->assertSame($expectRecorded, $this->isBlocked($firewall, $visitor));
    }

    /**
     * @return array<string, array{array<string, mixed>, bool}>
     */
    public static function recordingMetadata(): array
    {
        return [
            'unset' => [[], true],
            'explicitly true' => [['record' => true], true],
            'explicitly false' => [['record' => false], false],
            // Only a real boolean turns it off, the same way every other
            // boolean in this configuration behaves. `record: "false"` is a
            // non-empty string and means nothing.
            'the string "false"' => [['record' => 'false'], true],
            'a number' => [['record' => 0], true],
        ];
    }
}
