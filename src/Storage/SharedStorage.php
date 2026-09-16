<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * A block list shared across a fleet, that keeps working when the share is not (#223).
 *
 * Ten nodes behind a load balancer each learn about the same attacker
 * independently. An attacker gets ten times the budget before any single node
 * blocks them, a ban earned on node 3 does nothing on node 7, and
 * `blocking_escalation` counts one attacker ten times over -- once per node --
 * so the escalation that should have made the second offence expensive never
 * fires.
 *
 * Pointing every node at one Redis fixes all of that, and has been possible
 * since 2.22.0. What it costs is the thing this class exists for: with a shared
 * store and nothing else, **an unreachable Redis means no block list at all**.
 * `RedisStorage` degrades rather than throwing -- correctly, because a firewall
 * that stops serving because its block list is down helps nobody -- but what
 * it degrades to is answering "nothing is blocked" for every address, which is
 * a fail-open on the one list whose whole job is to say otherwise.
 *
 * ```yaml
 * storage:
 *   type: "\Kanopi\Firewall\Storage\SharedStorage"
 *   config:
 *     shared:
 *       type: "\Kanopi\Firewall\Storage\RedisStorage"
 *       config:
 *         redis: { host: redis.internal, port: 6379 }
 *     local:
 *       type: "\Kanopi\Firewall\Storage\FileStorage"
 *       config:
 *         storage_file: /var/lib/firewall/blocked.data
 * ```
 *
 * ## How it behaves
 *
 * | | Shared store reachable | Shared store unreachable |
 * |---|---|---|
 * | Reads | Shared, always | Local |
 * | Writes | Shared, **mirrored** to local | Local |
 *
 * Reads never come from local while the share is up, so a ban lifted on
 * another node applies here on the next request -- there is no propagation
 * delay to reason about, and no cache to go stale. The mirror exists so the
 * local copy is already warm when the share goes away, rather than the node
 * starting an outage knowing nothing.
 *
 * ## What an outage costs, precisely
 *
 * The node keeps enforcing every ban it had mirrored, and records new ones
 * locally, so an attacker blocked during an outage stays blocked on the node
 * that blocked them. What is lost is the *sharing*: for the length of the
 * outage the fleet is back to learning independently, and bans written locally
 * are not replayed to the share when it returns. They expire where they were
 * written.
 *
 * That is deliberate. Replaying an outage's worth of local writes into a
 * recovered share means reconciling ten nodes' disagreements about the same
 * address, and the conservative failure -- a ban that is enforced on one node
 * rather than ten -- is much better than the alternative, which is being wrong
 * about who is banned across the whole fleet.
 */
class SharedStorage extends AbstractStorageBase
{
    use LoggingTrait;

    /**
     * The store every node writes to.
     */
    protected StorageInterface $shared;

    /**
     * This node's own store, used when the shared one cannot be reached.
     */
    protected StorageInterface $local;

    /**
     * Whether the shared store has answered so far.
     *
     * Starts from whether it reported itself degraded while constructing --
     * which is how `RedisStorage` says it could not connect -- and is not
     * revisited per request. A share that comes back is picked up by the next
     * process, which for PHP-FPM is the next request or two.
     */
    protected bool $sharedIsUp;

    /**
     * @param array<string, mixed> $config
     *   `shared` and `local`, each a storage definition of the same shape
     *   `storage:` takes, plus nothing else.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->shared = $this->build($config['shared'] ?? null);
        $this->local = $this->build($config['local'] ?? null);

        // A backend that could not connect records itself while constructing
        // (#273), naming its own class, so the registry is the signal and no
        // new interface is needed to ask.
        //
        // Matched on the class rather than on how many entries appeared while
        // this constructor ran: a backend handed in already built -- a host
        // wiring its own connection, a test holding a reference -- recorded
        // itself before this object existed, and counting would have called it
        // healthy.
        $this->sharedIsUp = !$this->isDegraded($this->shared::class);

        if (!$this->sharedIsUp) {
            // Error, not warning: the fleet is no longer sharing anything, and
            // every node is now learning independently. That is the condition
            // this class exists to survive, not one to survive quietly.
            $this->getLogger()->error('Shared block list is unreachable - this node is enforcing from its local copy', [
                'shared' => $this->shared::class,
                'local' => $this->local::class,
            ]);

            DegradedBackends::record(
                'shared block list',
                $this->shared::class,
                'unreachable at startup; this node is enforcing from its local copy'
            );
        }
    }

    /**
     * Whether a backend has reported itself unreachable.
     *
     * @param string $class
     *   The backend's class name.
     *
     * @return bool
     *   TRUE when it is in the degraded registry.
     */
    private function isDegraded(string $class): bool
    {
        foreach (DegradedBackends::all() as $entry) {
            if ($entry['backend'] === $class) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build one side, from a definition or from something already built.
     *
     * An already-constructed backend is accepted for the same reason
     * `RedisStorage` takes an `instance`: a host wiring its own connection, and
     * a test that needs to hold a reference to the thing it is asserting
     * about. Anything else goes through the factory, which is what a `type` and
     * `config` in YAML resolve through.
     *
     * @param mixed $definition
     *   A `StorageInterface`, or a `{type, config}` block.
     *
     * @return StorageInterface
     *   The backend.
     */
    private function build(mixed $definition): StorageInterface
    {
        if ($definition instanceof StorageInterface) {
            return $definition;
        }

        return StorageFactory::create(is_array($definition) ? $definition : []);
    }

    /**
     * Whether this node is reading and writing the shared store.
     *
     * @return bool
     *   FALSE when the share was unreachable and the local copy is in use.
     */
    public function isSharing(): bool
    {
        return $this->sharedIsUp;
    }

    /**
     * The store reads are answered from.
     *
     * @return StorageInterface
     *   The shared store, or the local one during an outage.
     */
    protected function reader(): StorageInterface
    {
        return $this->sharedIsUp ? $this->shared : $this->local;
    }

    /**
     * {@inheritdoc}
     *
     * Written to the share, and mirrored locally so this node is not starting
     * from nothing if the share goes away.
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        if (!$this->sharedIsUp) {
            return $this->local->set($key, $value, $expire);
        }

        $stored = $this->shared->set($key, $value, $expire);

        // The mirror is best effort: a local copy that could not be written
        // costs coverage during a future outage, and nothing right now.
        $this->local->set($key, $value, $expire);

        return $stored;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->reader()->get($key, $default);
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        return $this->reader()->exists($key);
    }

    /**
     * {@inheritdoc}
     *
     * Deleted from both, whichever is answering. Lifting a ban has to lift it
     * here as well as for the fleet, or the node that ran the command keeps
     * enforcing what it was told to stop enforcing.
     */
    public function delete(string $key): bool
    {
        $deleted = $this->sharedIsUp ? $this->shared->delete($key) : true;

        return $this->local->delete($key) && $deleted;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        if (!$this->sharedIsUp) {
            return $this->local->addToExpire($key, $amount);
        }

        $extended = $this->shared->addToExpire($key, $amount);
        $this->local->addToExpire($key, $amount);

        return $extended;
    }

    /**
     * {@inheritdoc}
     *
     * The reason the fleet wants a shared store at all. Offences counted per
     * node mean `blocking_escalation` sees one attacker as ten first-time
     * offenders, and the escalation that should make a second offence
     * expensive never fires.
     */
    public function recordOffense(string $key): bool
    {
        if (!$this->sharedIsUp) {
            return $this->local->recordOffense($key);
        }

        $recorded = $this->shared->recordOffense($key);
        $this->local->recordOffense($key);

        return $recorded;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return $this->reader()->countOffenses($key, $start, $end);
    }

    /**
     * {@inheritdoc}
     */
    public function expire(): bool
    {
        $expired = $this->sharedIsUp ? $this->shared->expire() : true;

        return $this->local->expire() && $expired;
    }

    /**
     * {@inheritdoc}
     *
     * Both, because a reset that left the share populated would be undone by
     * the next read.
     */
    public function reset(): bool
    {
        $reset = $this->sharedIsUp ? $this->shared->reset() : true;

        return $this->local->reset() && $reset;
    }
}
