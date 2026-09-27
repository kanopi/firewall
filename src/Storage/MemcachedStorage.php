<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Traits\AddressMatchTrait;
use Kanopi\Firewall\Utility\DegradedBackends;
use Memcached;

/**
 * Blocked-client storage backed by Memcached (#392).
 *
 * For a fleet that has Memcached provisioned and not Redis. Blocks are keyed lookups on the
 * hot path, which Memcached does as well as anything; what it cannot do is list its own keys,
 * and `QueryableStorageInterface` needs exactly that. So this backend keeps an index of the
 * keys it has written, and answers `find()` and `deleteMatching()` from it.
 *
 * Four shapes are stored, all namespaced by `prefix`:
 *
 * - `{prefix}block:{key}` holds `{"v": record, "e": expires-at}` as JSON. The lifetime is
 *   also the item's own Memcached expiry, so a lapsed ban is removed by the server and
 *   `expire()` has nothing to do. `e` is kept alongside because Memcached cannot report
 *   the time an item has left, and both `find()` and `addToExpire()` need it.
 * - `{prefix}offense:{key}` holds `{"t": [timestamps]}`, with no expiry, capped at the most
 *   recent `MAX_OFFENSES`. Offenses outlive the block that earned them, as on every other
 *   backend, because `blocking_escalation` needs that history.
 * - `{prefix}index:{n}` is one of `INDEX_SHARDS` shards of `{"k": {key: expires-at}}`. A key
 *   lives in the shard its CRC32 picks. Sharded by hash rather than by address prefix: a
 *   fixed number of keys needs no directory of which ones exist, and a botnet concentrated
 *   in one range cannot overflow one shard.
 * - `{prefix}index:meta` records when the index was started, the latest expiry it has ever
 *   held, and whether part of it has been lost.
 *
 * **The index is best effort, and says when it is not complete.** Memcached is a cache: it
 * evicts under memory pressure and forgets everything on restart. Losing a block record is
 * losing the block, the same as a Redis without persistence. Losing an index shard is worse
 * in a quieter way -- the blocks are still enforced but `find()` cannot see them -- so a
 * missing shard is detected, recorded in the meta key, and reported through
 * `enumerationGap()` until every block it could have held has expired. Exact-address lookups
 * never use the index and are unaffected.
 *
 * Every index write is a compare-and-swap, retried a bounded number of times. Without it,
 * two workers blocking at once would each write back their own copy of the shard, and one
 * block would silently disappear from the index.
 *
 * JSON rather than PHP serialisation, as everywhere else this library writes and reads back
 * (CWE-502). Only strings are ever stored, so the extension never serialises anything of
 * ours. It will still unserialise an item that some *other* writer flagged as serialised --
 * that decision is made inside ext-memcached, before this class sees the value -- which is
 * one more reason a Memcached server must not be reachable by anything untrusted.
 */
class MemcachedStorage extends AbstractStorageBase implements QueryableStorageInterface, BestEffortEnumerationInterface
{
    use AddressMatchTrait;

    /**
     * Why the connection failed, when the reason is that there is no extension.
     */
    private const NO_EXTENSION = 'the memcached extension is not installed on this host';

    /**
     * How many shards the index is split across.
     *
     * Fixed rather than configurable: changing it would orphan every entry already
     * written, which is the loss this backend otherwise works to detect. At roughly 30
     * bytes an entry, before compression, 64 shards hold well over a million blocks
     * under Memcached's default 1 MB item limit.
     */
    public const INDEX_SHARDS = 64;

    /**
     * How many times a compare-and-swap is retried before giving up.
     */
    protected const CAS_ATTEMPTS = 8;

    /**
     * The most offense timestamps kept per key.
     *
     * An offense list is one item, and an item has a size limit. Escalation thresholds are
     * single figures, so the most recent thousand are every one that can matter.
     */
    public const MAX_OFFENSES = 1000;

    /**
     * The longest expiry Memcached reads as relative, in seconds (30 days).
     *
     * Anything larger is read as a unix timestamp. A ninety-day ban passed through as
     * seconds would be read as a moment in January 1970 -- already past -- and the block
     * would vanish the moment it was written.
     */
    protected const RELATIVE_TTL_LIMIT = 2592000;

    /**
     * The step the index horizon is rounded up to, in seconds.
     *
     * The horizon is only rewritten when a block outlives it, so rounding up to the hour
     * keeps a steady stream of bans from rewriting the meta key on every one of them.
     */
    protected const HORIZON_STEP = 3600;

    /**
     * Memcached's key length limit.
     */
    protected const MAX_KEY_LENGTH = 250;

    /**
     * Memcached connection, or null when one could not be established.
     */
    protected ?Memcached $memcached = null;

    /**
     * Namespace for every key this backend owns.
     */
    protected string $memcachedPrefix = 'firewall:';

    /**
     * Constructs a new MemcachedStorage object.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);

        try {
            $options = is_array($config['memcached'] ?? null) ? $config['memcached'] : [];
            $this->memcachedPrefix = strval($options['prefix'] ?? 'firewall:');

            $this->memcached = (($config['instance'] ?? null) instanceof Memcached)
                ? $config['instance']
                : $this->connect($options);

            // Adding a server opens nothing, so without asking for something a
            // host that is down would only be discovered on the first block.
            if (!$this->answers($this->memcached)) {
                throw new \RuntimeException(sprintf(
                    'no Memcached server answered (%s)',
                    $this->memcached->getResultMessage()
                ));
            }

            $this->getLogger()->info('Memcached storage initialized', [
                'prefix' => $this->memcachedPrefix,
            ]);
        } catch (\Throwable $throwable) {
            // `\Throwable`, for the reason RedisStorage gives: a missing
            // extension throws `\Error` from `new Memcached()`, and a firewall
            // that does not start is no protection at all (#356). Left null,
            // and every method below degrades rather than fatals.
            $this->memcached = null;

            $reason = extension_loaded('memcached') ? $throwable->getMessage() : self::NO_EXTENSION;

            $this->getLogger()->error('Failed to initialize Memcached storage', [
                'error' => $reason,
            ]);

            DegradedBackends::record('block list', self::class, $reason);
        }
    }

    /**
     * Does any configured server answer?
     *
     * A read rather than `getVersion()`, which reports failure when *any* server fails --
     * so one of three servers down would take the whole block list with it. A read goes
     * to one server; when that one has failed it is ejected and the next attempt is
     * routed to a live one. One attempt per server is enough to reach every server once.
     *
     * The key read is the index meta key, which also keeps it recently used.
     *
     * @param Memcached $memcached
     *   The client.
     *
     * @return bool
     *   TRUE when a server answered.
     */
    private function answers(Memcached $memcached): bool
    {
        $attempts = max(1, count($memcached->getServerList()));

        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $memcached->get($this->metaKey());

            if (in_array($memcached->getResultCode(), [Memcached::RES_SUCCESS, Memcached::RES_NOTFOUND], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build a client from the `memcached:` options.
     *
     * @param array<string, mixed> $options
     *   The `memcached:` block.
     *
     * @return Memcached
     *   A configured client. Nothing has been sent to the server yet.
     */
    protected function connect(array $options): Memcached
    {
        $memcached = new Memcached();

        // Bounded for the reason RedisStorage's are (#312): the case that hangs
        // is not the refused connection, which answers straight away, but the
        // silently dropped one -- a firewalled port, a wrong subnet.
        $connectTimeout = $this->seconds($options['connectTimeout'] ?? null);
        $readTimeout = $this->seconds($options['readTimeout'] ?? null);

        $memcached->setOption(Memcached::OPT_CONNECT_TIMEOUT, (int) round($connectTimeout * 1000));
        $memcached->setOption(Memcached::OPT_POLL_TIMEOUT, (int) round($readTimeout * 1000));
        $memcached->setOption(Memcached::OPT_SEND_TIMEOUT, (int) round($readTimeout * 1000000));
        $memcached->setOption(Memcached::OPT_RECV_TIMEOUT, (int) round($readTimeout * 1000000));

        // Consistent hashing, so every node in a fleet with several Memcached
        // servers maps a key to the same one -- and adding a server moves a
        // fraction of the keys rather than nearly all of them.
        $memcached->setOption(Memcached::OPT_LIBKETAMA_COMPATIBLE, true);

        // And a server that fails is taken out of that ring for the rest of
        // the request, so its keys land on the servers still up rather than
        // every one of them paying the connect timeout again.
        $memcached->setOption(Memcached::OPT_REMOVE_FAILED_SERVERS, true);
        $memcached->setOption(Memcached::OPT_SERVER_FAILURE_LIMIT, 1);

        if (is_string($options['username'] ?? null) && $options['username'] !== '') {
            // SASL is only spoken over the binary protocol.
            $memcached->setOption(Memcached::OPT_BINARY_PROTOCOL, true);
            $memcached->setSaslAuthData($options['username'], strval($options['password'] ?? ''));
        }

        $servers = $this->servers($options);

        // Checked here because a client with no servers does not fail: it
        // answers every read with "not found", which is a block list that is
        // silently empty.
        if ($servers === []) {
            throw new \RuntimeException('no usable Memcached server is configured');
        }

        $memcached->addServers($servers);

        return $memcached;
    }

    /**
     * A timeout option in seconds, defaulting to 1.5.
     *
     * @param mixed $value
     *   The configured value.
     *
     * @return float
     *   Seconds.
     */
    private function seconds(mixed $value): float
    {
        return is_numeric($value) && (float) $value > 0 ? (float) $value : 1.5;
    }

    /**
     * The servers to connect to.
     *
     * Either `servers:` -- a list of `host:port` strings or `{host, port}` maps -- or a single
     * `host` and `port`.
     *
     * @param array<string, mixed> $options
     *   The `memcached:` block.
     *
     * @return array<int, array{0: string, 1: int}>
     *   Host and port pairs.
     */
    private function servers(array $options): array
    {
        $declared = is_array($options['servers'] ?? null) && $options['servers'] !== []
            ? $options['servers']
            : [['host' => $options['host'] ?? '127.0.0.1', 'port' => $options['port'] ?? 11211]];

        $servers = [];

        foreach ($declared as $server) {
            if (is_string($server)) {
                // Split on the last colon, so an unbracketed IPv6 address keeps
                // its own colons.
                $colon = strrpos($server, ':');
                $server = $colon === false
                    ? ['host' => $server]
                    : ['host' => substr($server, 0, $colon), 'port' => substr($server, $colon + 1)];
            }

            if (!is_array($server) || !is_string($server['host'] ?? null) || $server['host'] === '') {
                $this->getLogger()->warning('Memcached server entry skipped - no host', [
                    'server' => is_scalar($server) ? (string) $server : gettype($server),
                ]);
                continue;
            }

            $port = $server['port'] ?? 11211;
            // `[2001:db8::1]:11211` is how an IPv6 server is usually written;
            // libmemcached wants the address without its brackets.
            $servers[] = [trim($server['host'], '[]'), is_numeric($port) ? (int) $port : 11211];
        }

        return $servers;
    }

    // -----------------------------------------------------------------------
    // StorageInterface
    // -----------------------------------------------------------------------

    /**
     * {@inheritdoc}
     *
     * The index is written before the record. The other order leaves a window in which a
     * block is enforced and invisible; this one leaves, at worst, an index entry pointing
     * at nothing, which every read already skips.
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        if (!$this->memcached instanceof Memcached) {
            return false;
        }

        // `$expire` is a TTL in seconds, matching every other backend. Zero is
        // a permanent ban.
        $expiresAt = $expire > 0 ? time() + $expire : 0;
        $encoded = $this->encode(['v' => $value, 'e' => $expiresAt], $key);

        if ($encoded === null) {
            return false;
        }

        $this->indexAdd($key, $expiresAt);

        if (!$this->memcached->set($this->blockKey($key), $encoded, $this->itemExpiry($expiresAt))) {
            $this->getLogger()->error('Failed to write to Memcached storage', [
                'key' => $key,
                'error' => $this->memcached->getResultMessage(),
            ]);

            return false;
        }

        $this->recordOffense($key);

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $record = $this->readRecord($key);

        return $record === null ? $default : $record['v'];
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        if (!$this->memcached instanceof Memcached) {
            return false;
        }

        $deleted = $this->memcached->delete($this->blockKey($key));

        if (!$deleted && $this->memcached->getResultCode() !== Memcached::RES_NOTFOUND) {
            $this->getLogger()->error('Failed to delete from Memcached storage', [
                'key' => $key,
                'error' => $this->memcached->getResultMessage(),
            ]);

            return false;
        }

        $this->indexRemove([$key]);

        return $deleted;
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        return $this->readRecord($key) !== null;
    }

    /**
     * {@inheritdoc}
     *
     * Nothing to do: every block carries a Memcached expiry, so the server has already
     * dropped what has lapsed. Index entries for lapsed blocks are pruned whenever their
     * shard is next written, and are filtered out of every read until then.
     */
    public function expire(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        if (!$this->memcached instanceof Memcached) {
            return false;
        }

        $extendedTo = 0;

        try {
            $extended = $this->mutate($this->blockKey($key), function (?array $record) use ($amount, &$extendedTo): ?array {
                // Missing, or permanent. Neither can be extended: there is
                // nothing to extend, or it is already forever.
                if ($record === null || !is_int($record['e'] ?? null) || $record['e'] === 0) {
                    return null;
                }

                $record['e'] += $amount;
                $extendedTo = $record['e'];

                return $record;
            }, true);
        } catch (\RuntimeException $runtimeException) {
            $this->getLogger()->error('Failed to extend expiry in Memcached storage', [
                'key' => $key,
                'error' => $runtimeException->getMessage(),
            ]);

            return false;
        }

        if ($extended) {
            // The index holds the expiry too, and prunes by it. Left stale, the
            // entry would be dropped while the block it points at is still in
            // force.
            $this->indexAdd($key, $extendedTo);
        }

        return $extended;
    }

    /**
     * {@inheritdoc}
     *
     * Clears everything the index knows about, then the index itself. A record the index
     * has lost cannot be found to be deleted; it expires with its own lifetime. `flush()` is
     * deliberately not used -- it would clear every other application sharing the server.
     */
    public function reset(): bool
    {
        if (!$this->memcached instanceof Memcached) {
            return false;
        }

        try {
            $keys = array_keys($this->indexEntries($this->readIndex()['shards']));
        } catch (\RuntimeException $runtimeException) {
            $this->getLogger()->error('Failed to reset Memcached storage', [
                'error' => $runtimeException->getMessage(),
            ]);

            return false;
        }

        $doomed = [$this->metaKey()];

        for ($shard = 0; $shard < self::INDEX_SHARDS; $shard++) {
            $doomed[] = $this->shardKey($shard);
        }

        foreach ($keys as $key) {
            $doomed[] = $this->blockKey($key);
            $doomed[] = $this->offenseKey($key);
        }

        $this->memcached->deleteMulti($doomed);

        $this->getLogger()->info('Memcached storage reset', ['records_deleted' => count($keys)]);

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        if (!$this->memcached instanceof Memcached) {
            return false;
        }

        $now = time();

        try {
            $recorded = $this->mutate($this->offenseKey($key), static function (?array $offenses) use ($now): array {
                $moments = is_array($offenses['t'] ?? null) ? $offenses['t'] : [];
                $moments[] = $now;

                return ['t' => array_slice($moments, -self::MAX_OFFENSES)];
            });
        } catch (\RuntimeException $runtimeException) {
            $this->getLogger()->error('Failed to record offense in Memcached storage', [
                'key' => $key,
                'error' => $runtimeException->getMessage(),
            ]);

            return false;
        }

        if (!$recorded) {
            $this->getLogger()->warning('Offense not recorded in Memcached storage - too much contention', [
                'key' => $key,
            ]);
        }

        return $recorded;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return count($this->offenseMoments($key, $start, $end));
    }

    // -----------------------------------------------------------------------
    // QueryableStorageInterface
    // -----------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function listOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX, int $limit = 50): array
    {
        $moments = $this->offenseMoments($key, $start, $end);
        rsort($moments);

        return $limit > 0 ? array_slice($moments, 0, $limit) : $moments;
    }

    /**
     * {@inheritdoc}
     *
     * A single address is looked up directly and never touches the index, so it is
     * answered correctly even when the index has lost entries -- which is the question
     * "why is this customer blocked?" usually is.
     */
    public function find(string $pattern): array
    {
        if (!$this->memcached instanceof Memcached) {
            return [];
        }

        if (!$this->isValidPattern($pattern)) {
            $this->getLogger()->warning('Storage find skipped - not a valid address or CIDR range', [
                'pattern' => $pattern,
            ]);

            return [];
        }

        try {
            if (!str_contains($pattern, '/')) {
                $candidates = [$pattern];
            } else {
                $index = $this->readIndex();
                $this->warnOfGap($index);

                $candidates = [];
                $now = time();

                foreach ($this->indexEntries($index['shards']) as $key => $expiresAt) {
                    if (($expiresAt === 0 || $expiresAt > $now) && $this->addressMatches((string) $key, $pattern)) {
                        $candidates[] = (string) $key;
                    }
                }
            }

            $matches = $this->describe($candidates);
        } catch (\RuntimeException $runtimeException) {
            $this->getLogger()->error('Failed to search Memcached storage', [
                'pattern' => $pattern,
                'error' => $runtimeException->getMessage(),
            ]);

            return [];
        }

        $this->getLogger()->debug('Storage find completed', [
            'pattern' => $pattern,
            'matches' => count($matches),
        ]);

        return $matches;
    }

    /**
     * {@inheritdoc}
     *
     * Single addresses are deleted directly, as in `find()`, so an exact un-block works
     * even for a block the index has lost.
     */
    public function deleteMatching(array $patterns): int
    {
        if (!$this->memcached instanceof Memcached) {
            return 0;
        }

        $patterns = $this->validPatterns($patterns);

        if ($patterns === []) {
            return 0;
        }

        $indexed = [];
        $exact = array_values(array_filter($patterns, static fn (string $pattern): bool => !str_contains($pattern, '/')));

        try {
            if (count($exact) < count($patterns)) {
                $index = $this->readIndex();
                $this->warnOfGap($index);

                // Lapsed entries included. Their records are already gone, but
                // their offense history is not, and an operator lifting a range
                // expects that history to go too.
                foreach (array_keys($this->indexEntries($index['shards'])) as $key) {
                    foreach ($patterns as $pattern) {
                        if ($this->addressMatches((string) $key, $pattern)) {
                            $indexed[(string) $key] = true;
                            break;
                        }
                    }
                }
            }
        } catch (\RuntimeException $runtimeException) {
            $this->getLogger()->error('Failed to delete matching records from Memcached storage', [
                'patterns' => $patterns,
                'error' => $runtimeException->getMessage(),
            ]);

            return 0;
        }

        $candidates = array_values(array_unique(array_merge($exact, array_map(strval(...), array_keys($indexed)))));
        $deleted = $this->deleteRecords($candidates, $indexed);

        $this->getLogger()->info('Storage records deleted by pattern', [
            'patterns' => $patterns,
            'deleted' => $deleted,
        ]);

        return $deleted;
    }

    // -----------------------------------------------------------------------
    // BestEffortEnumerationInterface
    // -----------------------------------------------------------------------

    /**
     * {@inheritdoc}
     */
    public function enumerationGap(): ?string
    {
        // Every answer from a store that could not be reached is empty, and
        // "nothing is blocked" is the one conclusion that must not be drawn
        // from it.
        if (!$this->memcached instanceof Memcached) {
            return 'no Memcached server could be reached, so nothing can be found';
        }

        try {
            return $this->gapIn($this->readIndex());
        } catch (\RuntimeException $runtimeException) {
            return 'the index could not be read: ' . $runtimeException->getMessage();
        }
    }

    // -----------------------------------------------------------------------
    // Records
    // -----------------------------------------------------------------------

    /**
     * Read a block record, or null when there is none to read.
     *
     * @param string $key
     *   Client key.
     *
     * @return array{v: mixed, e: int}|null
     *   The stored record.
     */
    protected function readRecord(string $key): ?array
    {
        if (!$this->memcached instanceof Memcached) {
            return null;
        }

        $raw = $this->memcached->get($this->blockKey($key));

        if ($raw === false) {
            if ($this->memcached->getResultCode() !== Memcached::RES_NOTFOUND) {
                $this->getLogger()->error('Failed to read from Memcached storage', [
                    'key' => $key,
                    'error' => $this->memcached->getResultMessage(),
                ]);
            }

            return null;
        }

        return $this->asRecord($raw, $key);
    }

    /**
     * Decode a stored block record.
     *
     * @param mixed $raw
     *   What Memcached returned.
     * @param string $key
     *   Client key, for the log.
     *
     * @return array{v: mixed, e: int}|null
     *   The record, or null when it is not one or has lapsed.
     */
    protected function asRecord(mixed $raw, string $key): ?array
    {
        $record = $this->decode($raw, $key);

        if (!is_array($record) || !array_key_exists('v', $record) || !is_int($record['e'] ?? null)) {
            // A value that cannot be decoded is not the same fact as no value.
            // Reported, because for a block list the default reads as "this
            // client is not blocked".
            $this->getLogger()->error('Memcached storage value could not be decoded', [
                'key' => $key,
            ]);

            return null;
        }

        // Memcached should already have dropped it. A server whose clock runs
        // behind this host's has not, and a lapsed ban is not in force.
        if ($record['e'] > 0 && $record['e'] <= time()) {
            return null;
        }

        return ['v' => $record['v'], 'e' => $record['e']];
    }

    /**
     * Describe live records for `find()`.
     *
     * @param array<int, string> $keys
     *   Client keys to look up.
     *
     * @return array<string, array<string, mixed>>
     *   Matching records keyed by address.
     */
    protected function describe(array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        $blockKeys = [];
        $offenseKeys = [];

        foreach ($keys as $key) {
            $blockKeys[$key] = $this->blockKey($key);
            $offenseKeys[$key] = $this->offenseKey($key);
        }

        $items = $this->getMany(array_merge(array_values($blockKeys), array_values($offenseKeys)));
        $matches = [];

        foreach ($blockKeys as $key => $blockKey) {
            // Absent: evicted, deleted, or lapsed since the index was read.
            if (!array_key_exists($blockKey, $items)) {
                continue;
            }

            $record = $this->asRecord($items[$blockKey], $key);

            if ($record === null) {
                continue;
            }

            $offenses = $this->decode($items[$offenseKeys[$key]] ?? null, $key);

            $matches[$key] = [
                'value' => $record['v'],
                'expire' => $record['e'],
                'expires_at' => $record['e'] > 0 ? date('c', $record['e']) : null,
                'offenses' => is_array($offenses) && is_array($offenses['t'] ?? null) ? count($offenses['t']) : 0,
            ];
        }

        return $matches;
    }

    /**
     * Delete block records and their offense history.
     *
     * @param array<int, string> $keys
     *   Client keys.
     * @param array<string, true> $indexed
     *   The keys the index knew about. Their offenses go whether or not the block was
     *   still there to delete; an exact address the index never held keeps its history
     *   unless it really was blocked.
     *
     * @return int
     *   How many block records were deleted.
     */
    protected function deleteRecords(array $keys, array $indexed): int
    {
        if ($keys === []) {
            return 0;
        }

        $memcached = $this->client();

        $blockKeys = [];

        foreach ($keys as $key) {
            $blockKeys[$this->blockKey($key)] = $key;
        }

        $results = $memcached->deleteMulti(array_keys($blockKeys));
        $deleted = 0;
        $offenseKeys = [];
        $forget = [];

        foreach ($blockKeys as $blockKey => $key) {
            $gone = ($results[$blockKey] ?? false) === true;

            if ($gone) {
                $deleted++;
            }

            // Offenses go with the block, for the reason every backend gives:
            // left behind, `blocking_escalation` would escalate an address an
            // operator just un-blocked straight back to a longer ban.
            if ($gone || isset($indexed[$key])) {
                $offenseKeys[] = $this->offenseKey($key);
                $forget[] = $key;
            }
        }

        if ($offenseKeys !== []) {
            $memcached->deleteMulti($offenseKeys);
        }

        $this->indexRemove($forget);

        return $deleted;
    }

    /**
     * Offense timestamps within a window.
     *
     * @param string $key
     *   Client key.
     * @param int $start
     *   Window start.
     * @param int $end
     *   Window end.
     *
     * @return array<int, int>
     *   Timestamps, in the order they were recorded.
     */
    protected function offenseMoments(string $key, int $start, int $end): array
    {
        if (!$this->memcached instanceof Memcached) {
            return [];
        }

        $raw = $this->memcached->get($this->offenseKey($key));

        if ($raw === false) {
            // Logged rather than answered with a silent zero. A count that
            // could not be taken is not the same fact as a count of none --
            // the mistake #181 fixed in DatabaseStorage.
            if ($this->memcached->getResultCode() !== Memcached::RES_NOTFOUND) {
                $this->getLogger()->error('Failed to read offenses from Memcached storage', [
                    'key' => $key,
                    'error' => $this->memcached->getResultMessage(),
                ]);
            }

            return [];
        }

        $offenses = $this->decode($raw, $key);
        $moments = is_array($offenses) && is_array($offenses['t'] ?? null) ? $offenses['t'] : [];

        return array_values(array_filter(
            array_map(intval(...), $moments),
            static fn (int $moment): bool => $moment >= $start && $moment <= $end
        ));
    }

    // -----------------------------------------------------------------------
    // The index
    // -----------------------------------------------------------------------

    /**
     * Record that a key exists, and until when.
     *
     * A failure is logged and recorded rather than returned: the block itself is written
     * regardless, and still enforced. What is lost is the ability to find it by range.
     *
     * @param string $key
     *   Client key.
     * @param int $expiresAt
     *   Unix timestamp, or 0 for never.
     */
    protected function indexAdd(string $key, int $expiresAt): void
    {
        $this->editIndex($this->shardOf($key), static function (array $entries) use ($key, $expiresAt): array {
            $entries[$key] = $expiresAt;

            return $entries;
        }, $expiresAt, $key);
    }

    /**
     * Forget keys, grouped so each shard is rewritten once.
     *
     * @param array<int, string> $keys
     *   Client keys.
     */
    protected function indexRemove(array $keys): void
    {
        $byShard = [];

        foreach ($keys as $key) {
            $byShard[$this->shardOf($key)][] = $key;
        }

        foreach ($byShard as $shard => $shardKeys) {
            $this->editIndex($shard, static function (array $entries) use ($shardKeys): array {
                foreach ($shardKeys as $shardKey) {
                    unset($entries[$shardKey]);
                }

                return $entries;
            }, null, implode(',', $shardKeys));
        }
    }

    /**
     * Rewrite one shard, under compare-and-swap.
     *
     * @param int $shard
     *   Shard number.
     * @param callable(array<string, int>): array<string, int> $edit
     *   Receives the shard's live entries, returns the new set.
     * @param int|null $expiresAt
     *   The expiry being added, for the horizon; null when only removing.
     * @param string $subject
     *   What is being written, for the log.
     */
    protected function editIndex(int $shard, callable $edit, ?int $expiresAt, string $subject): void
    {
        try {
            $this->prepareShard($shard, $expiresAt);

            $now = time();
            $written = $this->mutate($this->shardKey($shard), static function (?array $document) use ($edit, $now): array {
                $entries = is_array($document['k'] ?? null) ? $document['k'] : [];

                // Pruned on every write rather than in a sweep: the shard has
                // already been read, so dropping what has lapsed costs nothing.
                $entries = array_filter($entries, static fn (mixed $at): bool => is_int($at) && ($at === 0 || $at > $now));

                return ['k' => $edit($entries)];
            });
        } catch (\RuntimeException $runtimeException) {
            $this->indexWriteFailed($subject, $runtimeException->getMessage());

            return;
        }

        if (!$written) {
            $this->indexWriteFailed($subject, sprintf('shard %d was rewritten by another worker %d times running', $shard, self::CAS_ATTEMPTS));
        }
    }

    /**
     * Make sure the meta key and the shard about to be written both exist, and note it
     * when one of them has been lost.
     *
     * @param int $shard
     *   Shard number.
     * @param int|null $expiresAt
     *   The expiry about to be indexed, for the horizon.
     */
    protected function prepareShard(int $shard, ?int $expiresAt): void
    {
        // Read together, and on every write. That is also what keeps the meta
        // key the most recently used item this backend owns, which is what
        // keeps it from being the first thing Memcached evicts.
        $items = $this->getMany([$this->metaKey(), $this->shardKey($shard)]);
        $meta = $this->decode($items[$this->metaKey()] ?? null, 'index meta');

        // A shard that is there and cannot be read is as lost as one that is
        // not there: the write below would replace it with an empty one.
        $document = $this->decode($items[$this->shardKey($shard)] ?? null, 'index shard');
        $shardReadable = is_array($document) && is_array($document['k'] ?? null);

        if (!is_array($meta)) {
            $this->initializeIndex();
            $meta = null;
        } elseif (!$shardReadable) {
            $this->shardLost($meta, $shard);
        }

        if ($expiresAt !== null && !$this->horizonCovers($meta, $expiresAt)) {
            $this->extendHorizon($expiresAt);
        }
    }

    /**
     * Does the index horizon, as last read, already cover an expiry?
     *
     * Checked before the meta key is rewritten, so that a steady stream of bans costs a
     * read of it rather than a compare-and-swap on it.
     *
     * @param array<string, mixed>|null $meta
     *   The meta key as read, or null when it has just been created.
     * @param int $expiresAt
     *   Unix timestamp, or 0 for never.
     *
     * @return bool
     *   TRUE when nothing needs writing.
     */
    protected function horizonCovers(?array $meta, int $expiresAt): bool
    {
        $horizon = $meta['horizon'] ?? null;

        return $horizon === 0 || ($expiresAt !== 0 && is_int($horizon) && $horizon >= $expiresAt);
    }

    /**
     * Start an index, or notice that one was here and lost its meta key.
     */
    protected function initializeIndex(): void
    {
        $memcached = $this->client();

        $shardKeys = [];

        for ($shard = 0; $shard < self::INDEX_SHARDS; $shard++) {
            $shardKeys[] = $this->shardKey($shard);
        }

        $present = $this->getMany($shardKeys);

        // Shards without their meta key: an index that was here, and whose
        // record of what it had held is gone. How far back the loss reaches
        // cannot be known, so it is reported until the index is reset.
        $meta = ['started' => time(), 'horizon' => null, 'lost' => null];

        if ($present !== []) {
            $meta['horizon'] = 0;
            $meta['lost'] = ['since' => time(), 'until' => 0, 'what' => 'the index meta key'];
        }

        // `add`, so two workers starting an index at once cannot overwrite
        // each other; whichever loses reads the winner's.
        $memcached->add($this->metaKey(), (string) $this->encode($meta, 'index meta'));

        foreach ($shardKeys as $shardKey) {
            if (!array_key_exists($shardKey, $present)) {
                $memcached->add($shardKey, '{"k":{}}');
            }
        }

        if ($meta['lost'] !== null) {
            $this->getLogger()->warning('Memcached block list index lost its meta key - range searches may be incomplete');
        }
    }

    /**
     * Record that a shard has been evicted, then recreate it.
     *
     * @param array<string, mixed> $meta
     *   The meta key as read.
     * @param int $shard
     *   The missing shard.
     */
    protected function shardLost(array $meta, int $shard): void
    {
        $memcached = $this->client();

        $horizon = $meta['horizon'] ?? null;

        // Nothing indexed has ever outlived this moment, so whatever the shard
        // held has lapsed anyway. Also true of an index that has never held an
        // entry, whose horizon is still null.
        $mattered = $horizon === 0 || (is_int($horizon) && $horizon > time());

        if ($mattered) {
            $this->mutate($this->metaKey(), static function (?array $current) use ($horizon, $shard): array {
                $current ??= ['started' => time(), 'horizon' => $horizon];
                $lost = is_array($current['lost'] ?? null) ? $current['lost'] : null;
                $until = (int) $horizon;

                // A loss that has already healed is not extended by a new one;
                // the new one starts its own window.
                if ($lost !== null && (int) ($lost['until'] ?? 0) > 0 && (int) $lost['until'] <= time()) {
                    $lost = null;
                }

                if ($lost !== null) {
                    $previous = (int) ($lost['until'] ?? 0);
                    $until = ($previous === 0 || $until === 0) ? 0 : max($previous, $until);
                }

                $current['lost'] = [
                    'since' => (int) ($lost['since'] ?? time()),
                    'until' => $until,
                    'what' => sprintf('index shard %d', $shard),
                ];

                return $current;
            });

            $this->getLogger()->warning('Memcached block list index shard was evicted - range searches may be incomplete', [
                'shard' => $shard,
                'until' => $horizon === 0 ? 'reset' : date('c', (int) $horizon),
            ]);
        }

        $memcached->add($this->shardKey($shard), '{"k":{}}');
    }

    /**
     * Push the index horizon out to cover a new expiry.
     *
     * @param int $expiresAt
     *   Unix timestamp, or 0 for never.
     */
    protected function extendHorizon(int $expiresAt): void
    {
        $needed = $expiresAt === 0 ? 0 : (int) (ceil($expiresAt / self::HORIZON_STEP) * self::HORIZON_STEP);

        $this->mutate($this->metaKey(), static function (?array $meta) use ($needed): ?array {
            if ($meta === null) {
                return null;
            }

            $horizon = $meta['horizon'] ?? null;

            // Zero is "forever" and cannot be exceeded; a later horizon already
            // covers this one.
            if ($horizon === 0 || (is_int($horizon) && $needed !== 0 && $horizon >= $needed)) {
                return null;
            }

            $meta['horizon'] = $needed;

            return $meta;
        });
    }

    /**
     * Log and record an index write that did not happen.
     *
     * @param string $subject
     *   What was being indexed.
     * @param string $reason
     *   Why it was not.
     */
    protected function indexWriteFailed(string $subject, string $reason): void
    {
        $this->getLogger()->error('Failed to update the Memcached block list index - the block is enforced but a range search will not find it', [
            'key' => $subject,
            'error' => $reason,
        ]);

        DegradedBackends::record('block list index', self::class, $reason);
    }

    /**
     * Read the meta key and every shard in one round trip.
     *
     * @return array{meta: array<string, mixed>|null, shards: array<int, array<string, int>|null>}
     *   Each shard's entries, or null for a shard that is missing.
     */
    protected function readIndex(): array
    {
        $keys = [$this->metaKey()];

        for ($shard = 0; $shard < self::INDEX_SHARDS; $shard++) {
            $keys[] = $this->shardKey($shard);
        }

        $items = $this->getMany($keys);
        $meta = $this->decode($items[$this->metaKey()] ?? null, 'index meta');
        $shards = [];

        for ($shard = 0; $shard < self::INDEX_SHARDS; $shard++) {
            $document = $this->decode($items[$this->shardKey($shard)] ?? null, 'index shard');
            $shards[$shard] = is_array($document) && is_array($document['k'] ?? null) ? $document['k'] : null;
        }

        return ['meta' => is_array($meta) ? $meta : null, 'shards' => $shards];
    }

    /**
     * Every entry across the shards that were read.
     *
     * @param array<int, array<string, int>|null> $shards
     *   Shards, as `readIndex()` returns them.
     *
     * @return array<string, int>
     *   Key to expiry.
     */
    protected function indexEntries(array $shards): array
    {
        $entries = [];

        foreach ($shards as $shard) {
            foreach ($shard ?? [] as $key => $expiresAt) {
                $entries[(string) $key] = (int) $expiresAt;
            }
        }

        return $entries;
    }

    /**
     * Why the index may be missing entries, from a read of it.
     *
     * @param array{meta: array<string, mixed>|null, shards: array<int, array<string, int>|null>} $index
     *   As `readIndex()` returns it.
     *
     * @return string|null
     *   The gap, or null when there is none.
     */
    protected function gapIn(array $index): ?string
    {
        $meta = $index['meta'];
        $missing = array_keys(array_filter($index['shards'], static fn (?array $shard): bool => $shard === null));

        if ($meta === null) {
            // No meta key and no shards: an index never started, or a server
            // that restarted and lost the blocks along with it. Either way
            // there is nothing the index should be finding.
            if (count($missing) === self::INDEX_SHARDS) {
                return null;
            }

            return 'the index has lost its meta key, so how much of it is missing cannot be known; '
                . 'blocks written before then may not appear in a range search';
        }

        $now = time();
        $horizon = $meta['horizon'] ?? null;
        $lost = is_array($meta['lost'] ?? null) ? $meta['lost'] : null;
        $gaps = [];

        if ($lost !== null) {
            $until = (int) ($lost['until'] ?? 0);

            if ($until === 0 || $until > $now) {
                $gaps[] = sprintf(
                    'part of the index (%s) was evicted at %s; blocks written before then may not appear in a range search %s',
                    is_string($lost['what'] ?? null) ? $lost['what'] : 'a shard',
                    date('Y-m-d H:i:s', (int) ($lost['since'] ?? $now)),
                    $until === 0 ? 'until the store is reset' : 'until ' . date('Y-m-d H:i:s', $until)
                );
            }
        }

        // Missing now and not yet noticed by a write. Only a gap if anything it
        // held could still be in force.
        if ($missing !== [] && ($horizon === 0 || (is_int($horizon) && $horizon > $now))) {
            $gaps[] = sprintf(
                '%d of %d index shards %s missing, so blocks recorded in %s may not appear in a range search',
                count($missing),
                self::INDEX_SHARDS,
                count($missing) === 1 ? 'is' : 'are',
                count($missing) === 1 ? 'it' : 'them'
            );
        }

        return $gaps === [] ? null : implode('; ', $gaps);
    }

    /**
     * Log a gap in the index, when there is one.
     *
     * @param array{meta: array<string, mixed>|null, shards: array<int, array<string, int>|null>} $index
     *   As `readIndex()` returns it.
     */
    protected function warnOfGap(array $index): void
    {
        $gap = $this->gapIn($index);

        if ($gap !== null) {
            $this->getLogger()->warning('Memcached block list search may be incomplete', ['reason' => $gap]);
        }
    }

    // -----------------------------------------------------------------------
    // Memcached primitives
    // -----------------------------------------------------------------------

    /**
     * Read-modify-write one item under compare-and-swap.
     *
     * @param string $item
     *   The Memcached key.
     * @param callable(array<string, mixed>|null): (array<string, mixed>|null) $change
     *   Receives the decoded document, or null when there is none. Returns the new
     *   document, or null to write nothing.
     * @param bool $expiresWithRecord
     *   Give the item the expiry held in its own `e` field, as a block record does. Every
     *   other item this backend writes has none.
     *
     * @return bool
     *   TRUE when written, FALSE when `$change` declined or the retries ran out.
     *
     * @throws \RuntimeException
     *   When the server fails for any reason other than contention.
     */
    protected function mutate(string $item, callable $change, bool $expiresWithRecord = false): bool
    {
        $memcached = $this->client();

        for ($attempt = 0; $attempt < self::CAS_ATTEMPTS; $attempt++) {
            $current = $memcached->get($item, null, Memcached::GET_EXTENDED);

            if ($current === false && $memcached->getResultCode() !== Memcached::RES_NOTFOUND) {
                throw new \RuntimeException($memcached->getResultMessage());
            }

            $document = is_array($current) ? $this->decode($current['value'], $item) : null;
            $next = $change(is_array($document) ? $document : null);

            if ($next === null) {
                return false;
            }

            $encoded = $this->encode($next, $item);

            // @codeCoverageIgnoreStart
            // Every document passed through here was either decoded from JSON
            // -- a block record being extended -- or built from integers and
            // the keys already in it, so it always re-encodes. Checked because
            // `encode()` can fail in general, and writing a null would erase the
            // item rather than leave it.
            if ($encoded === null) {
                throw new \RuntimeException('the value could not be encoded');
            }

            // @codeCoverageIgnoreEnd

            $expiry = $expiresWithRecord ? $this->itemExpiry((int) ($next['e'] ?? 0)) : 0;

            $stored = is_array($current)
                ? $memcached->cas($current['cas'], $item, $encoded, $expiry)
                : $memcached->add($item, $encoded, $expiry);

            if ($stored) {
                return true;
            }

            // Somebody else wrote it first -- or, for `add`, created it first,
            // or deleted it between the read and the swap. Read it again.
            $code = $memcached->getResultCode();

            if (!in_array($code, [Memcached::RES_DATA_EXISTS, Memcached::RES_NOTSTORED, Memcached::RES_NOTFOUND], true)) {
                throw new \RuntimeException($memcached->getResultMessage());
            }
        }

        return false;
    }

    /**
     * The connection, for helpers only public methods reach.
     *
     * Every public method returns early on a failed connection, so this cannot throw from
     * any path that exists today. It is here so that a helper cannot silently do nothing
     * if a future caller forgets to check.
     *
     * @return Memcached
     *   The client.
     */
    protected function client(): Memcached
    {
        return $this->memcached ?? throw new \LogicException('MemcachedStorage has no connection; the caller should have checked.');
    }

    /**
     * Read several items in one round trip.
     *
     * @param array<int, string> $items
     *   Memcached keys.
     *
     * @return array<string, mixed>
     *   Found items, keyed by Memcached key. Missing ones are absent.
     *
     * @throws \RuntimeException
     *   When the server could not be read, which is not the same fact as nothing found.
     */
    protected function getMany(array $items): array
    {
        $memcached = $this->client();

        $found = $memcached->getMulti($items);

        if ($found === false) {
            throw new \RuntimeException($memcached->getResultMessage());
        }

        return $found;
    }

    /**
     * Encode a document as JSON.
     *
     * @param array<string, mixed> $document
     *   The document.
     * @param string $key
     *   What it is for, for the log.
     *
     * @return string|null
     *   JSON, or null when it cannot be encoded.
     */
    protected function encode(array $document, string $key): ?string
    {
        try {
            return json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $jsonException) {
            $this->getLogger()->error('Failed to encode value for Memcached storage', [
                'key' => $key,
                'error' => $jsonException->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * Decode a stored JSON document.
     *
     * @param mixed $raw
     *   What Memcached returned.
     * @param string $key
     *   What it is, for the log.
     *
     * @return mixed
     *   The decoded value, or null when there is nothing decodable.
     */
    protected function decode(mixed $raw, string $key): mixed
    {
        if (!is_string($raw)) {
            return null;
        }

        try {
            return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            $this->getLogger()->error('Memcached storage value could not be decoded', [
                'key' => $key,
                'error' => $jsonException->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * The expiry to hand Memcached for an absolute moment.
     *
     * Relative where Memcached reads it as relative, so a clock difference between this
     * host and the server does not shorten or lengthen a ban; absolute beyond 30 days,
     * where it has no choice.
     *
     * @param int $expiresAt
     *   Unix timestamp, or 0 for never.
     *
     * @return int
     *   A Memcached expiry.
     */
    protected function itemExpiry(int $expiresAt): int
    {
        if ($expiresAt === 0) {
            return 0;
        }

        $remaining = max(1, $expiresAt - time());

        return $remaining <= self::RELATIVE_TTL_LIMIT ? $remaining : $expiresAt;
    }

    // -----------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------

    /**
     * Which shard a key is indexed in.
     *
     * @param string $key
     *   Client key.
     *
     * @return int
     *   Shard number.
     */
    protected function shardOf(string $key): int
    {
        return crc32($key) % self::INDEX_SHARDS;
    }

    /**
     * The Memcached key holding a client's block record.
     *
     * @param string $key
     *   Client key, normally an address.
     *
     * @return string
     *   Namespaced Memcached key.
     */
    protected function blockKey(string $key): string
    {
        return $this->itemKey('block:', $key);
    }

    /**
     * The Memcached key holding a client's offense history.
     *
     * @param string $key
     *   Client key, normally an address.
     *
     * @return string
     *   Namespaced Memcached key.
     */
    protected function offenseKey(string $key): string
    {
        return $this->itemKey('offense:', $key);
    }

    /**
     * The Memcached key holding one index shard.
     *
     * @param int $shard
     *   Shard number.
     *
     * @return string
     *   Namespaced Memcached key.
     */
    protected function shardKey(int $shard): string
    {
        return $this->memcachedPrefix . 'index:' . $shard;
    }

    /**
     * The Memcached key holding the index's own bookkeeping.
     *
     * @return string
     *   Namespaced Memcached key.
     */
    protected function metaKey(): string
    {
        return $this->memcachedPrefix . 'index:meta';
    }

    /**
     * A namespaced key Memcached will accept.
     *
     * Memcached refuses keys over 250 bytes or containing whitespace or control characters.
     * An address never is, but `set()` is the interface's general key/value write, so a key
     * that would be refused is hashed instead. The index keeps the original key, which is
     * what `find()` matches against.
     *
     * @param string $kind
     *   `block:` or `offense:`.
     * @param string $key
     *   Client key.
     *
     * @return string
     *   Namespaced Memcached key.
     */
    protected function itemKey(string $kind, string $key): string
    {
        $item = $this->memcachedPrefix . $kind . $key;

        if (strlen($item) > self::MAX_KEY_LENGTH || preg_match('/[\x00-\x20\x7f]/', $key) === 1) {
            return $this->memcachedPrefix . $kind . '#' . hash('sha256', $key);
        }

        return $item;
    }
}
