<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Storage;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\SharedStorage;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * A block list shared across a fleet, and what happens when the share is not (#223).
 *
 * Ten nodes behind a load balancer learn about the same attacker ten times, and
 * `blocking_escalation` counts one attacker as ten first-time offenders. One
 * Redis fixes that and has since 2.22.0 — at the cost of the block list
 * disappearing entirely when Redis does, because `RedisStorage` degrades by
 * answering "nothing is blocked" for every address.
 *
 * So the assertions worth reading are the outage ones: a node that cannot reach
 * the share must keep enforcing what it already knew, and must keep recording
 * what it learns.
 */
final class SharedStorageTest extends AbstractTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        DegradedBackends::reset();
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * Writes reach the share, which is the whole point.
     */
    public function testAWriteGoesToTheSharedStore(): void
    {
        $shared = new InMemoryStorage();
        $storage = $this->storage($shared, new InMemoryStorage());

        $storage->set('203.0.113.5', ['reason' => 'test'], 60);

        $this->assertNotFalse($shared->isBlocked('203.0.113.5'), 'The fleet has to be able to see it.');
    }

    /**
     * And are mirrored locally, so an outage does not start from nothing.
     *
     * The mirror is the difference between a node that keeps enforcing the
     * bans it knew about and one that forgets every one of them the moment the
     * share goes away.
     */
    public function testAWriteIsMirroredLocally(): void
    {
        $local = new InMemoryStorage();
        $storage = $this->storage(new InMemoryStorage(), $local);

        $storage->set('203.0.113.5', ['reason' => 'test'], 60);

        $this->assertNotFalse($local->isBlocked('203.0.113.5'));
    }

    /**
     * Reads come from the share while it is up, never from the mirror.
     *
     * A ban lifted on another node has to apply here on the next request. If
     * reads preferred the local copy there would be a propagation delay to
     * reason about, and a stale local entry would keep enforcing a ban the
     * fleet had already dropped.
     */
    public function testReadsComeFromTheShareWhileItIsUp(): void
    {
        $shared = new InMemoryStorage();
        $local = new InMemoryStorage();
        $storage = $this->storage($shared, $local);

        $storage->set('203.0.113.5', ['reason' => 'test'], 60);

        // Another node lifts it. The local mirror still has it.
        $shared->delete('203.0.113.5');

        $this->assertFalse($storage->isBlocked('203.0.113.5'), 'The share is authoritative while it answers.');
        $this->assertNotFalse($local->isBlocked('203.0.113.5'), 'And the stale mirror is still there, unread.');
    }

    /**
     * A node that cannot reach the share keeps enforcing from its mirror.
     *
     * The assertion this class exists for. Without it the same outage means
     * every address is unblocked, on every node, at once — which is a
     * fail-open on the one list whose job is to say otherwise.
     */
    public function testAnOutageKeepsEnforcingWhatWasAlreadyKnown(): void
    {
        $local = new InMemoryStorage();
        $local->set('203.0.113.5', ['reason' => 'banned earlier'], 60);

        $storage = $this->storage(new UnreachableStorage(), $local);

        $this->assertFalse($storage->isSharing());
        $this->assertNotFalse(
            $storage->isBlocked('203.0.113.5'),
            'A ban the node already had must survive the share going away.'
        );
    }

    /**
     * And keeps recording what it learns during one.
     */
    public function testAnOutageStillRecordsNewBans(): void
    {
        $local = new InMemoryStorage();
        $storage = $this->storage(new UnreachableStorage(), $local);

        $storage->set('198.51.100.9', ['reason' => 'during the outage'], 60);
        $storage->recordOffense('198.51.100.9');

        $this->assertNotFalse($storage->isBlocked('198.51.100.9'));
        $this->assertNotFalse($local->isBlocked('198.51.100.9'), 'Written where this node can still read it.');

        // Compared against the local store rather than a number: every backend
        // counts a ban itself as an offence, so the figure is two rather than
        // the one this obviously reads as. What matters is that the reads and
        // the writes went to the same place.
        $this->assertSame($local->countOffenses('198.51.100.9'), $storage->countOffenses('198.51.100.9'));
        $this->assertGreaterThan(0, $storage->countOffenses('198.51.100.9'));
    }

    /**
     * An outage is reported, not survived quietly.
     *
     * The fleet is no longer sharing anything and every node is back to
     * learning independently. That is the condition this class exists to
     * survive, which is not the same as one to keep to itself.
     */
    public function testAnOutageIsRecordedAsADegradedBackend(): void
    {
        $this->storage(new UnreachableStorage(), new InMemoryStorage());

        $components = array_column(DegradedBackends::all(), 'component');

        $this->assertContains('shared block list', $components);
    }

    /**
     * Offences go to the share, which is why escalation finally works.
     *
     * `blocking_escalation` lengthens a ban by how often an address has
     * offended. Counted per node, ten nodes see one attacker as ten
     * first-timers and the escalation never fires.
     */
    public function testOffencesAreCountedOnceForTheFleet(): void
    {
        $shared = new InMemoryStorage();
        $storage = $this->storage($shared, new InMemoryStorage());

        // Three nodes, one attacker: three SharedStorage instances over one
        // shared store, which is what a fleet is.
        $this->storage($shared, new InMemoryStorage())->recordOffense('203.0.113.5');
        $this->storage($shared, new InMemoryStorage())->recordOffense('203.0.113.5');
        $storage->recordOffense('203.0.113.5');

        $this->assertSame(3, $storage->countOffenses('203.0.113.5'));
    }

    /**
     * Lifting a ban lifts it here as well as for the fleet.
     *
     * The node that ran the command has a mirror of its own, and leaving it
     * there means that node keeps enforcing what it was told to stop
     * enforcing.
     */
    public function testDeletingLiftsTheLocalMirrorToo(): void
    {
        $local = new InMemoryStorage();
        $storage = $this->storage(new InMemoryStorage(), $local);

        $storage->set('203.0.113.5', ['reason' => 'test'], 60);
        $storage->delete('203.0.113.5');

        $this->assertFalse($local->isBlocked('203.0.113.5'));
    }

    /**
     * The remaining operations follow the same rule, up and down.
     *
     * `exists()`, `addToExpire()` and `reset()` are the rest of the interface,
     * and each has both a shared path and an outage path. Asserted together
     * because the rule is one rule -- reads from whoever is answering, writes
     * to the share and the mirror -- and a table is a clearer way to say that
     * than three near-identical tests.
     */
    public function testTheRestOfTheInterfaceFollowsTheSameRule(): void
    {
        $shared = new InMemoryStorage();
        $local = new InMemoryStorage();
        $storage = $this->storage($shared, $local);

        $storage->set('203.0.113.5', ['reason' => 'test'], 60);

        $this->assertTrue($storage->exists('203.0.113.5'), 'Read from the share while it answers.');
        $this->assertTrue($storage->addToExpire('203.0.113.5', 60));
        $this->assertTrue($storage->reset());
        $this->assertFalse($shared->exists('203.0.113.5'), 'A reset has to clear the share...');
        $this->assertFalse($local->exists('203.0.113.5'), '...and the mirror, or the next read restores it.');
    }

    /**
     * And during an outage they use the local copy instead.
     */
    public function testTheRestOfTheInterfaceUsesTheLocalCopyDuringAnOutage(): void
    {
        $local = new InMemoryStorage();
        $storage = $this->storage(new UnreachableStorage(), $local);

        $storage->set('198.51.100.9', ['reason' => 'during the outage'], 60);

        $this->assertTrue($storage->exists('198.51.100.9'));
        $this->assertTrue($storage->addToExpire('198.51.100.9', 60));
        $this->assertTrue($storage->reset());
        $this->assertFalse($local->exists('198.51.100.9'));
    }

    /**
     * A shared store that answers is reported as sharing.
     */
    public function testItSaysWhetherItIsSharing(): void
    {
        $this->assertTrue($this->storage(new InMemoryStorage(), new InMemoryStorage())->isSharing());
    }

    /**
     * Build one node's storage over a given pair.
     */
    private function storage(StorageInterface $shared, StorageInterface $local): SharedStorage
    {
        return new SharedStorage(['shared' => $shared, 'local' => $local]);
    }
}

/**
 * A store that reports itself unreachable while constructing.
 *
 * Which is how `RedisStorage` says it could not connect (#273) — the registry
 * entry is the signal, so a double only has to make the same one.
 */
class UnreachableStorage extends InMemoryStorage
{
    /**
     * @param array<string, mixed> $config
     *   Ignored.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        DegradedBackends::record('block list', self::class, 'connection refused');
    }
}
