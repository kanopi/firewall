<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;

/**
 * Read and lift blocks, from a configuration rather than from a script.
 *
 * `QueryableStorageInterface` was built for this and has been implemented by every shipped
 * backend since 2.19.0: `find()` answers "who is blocked in this range, and why",
 * `deleteMatching()` lifts a block that should not have been applied, `listOffenses()` says
 * when a client offended rather than only how often. The only documented way to reach any of
 * it was to write PHP -- which is a poor thing to be doing while somebody is on the phone
 * about a customer who cannot check out (#291).
 *
 * ## It is only useful against the real store
 *
 * `bin/firewall-check` deliberately swaps in a throwaway so that checking a request cannot
 * ban anybody. This is the opposite: pointed at a throwaway it would report nothing blocked,
 * truthfully and uselessly, and an operator would conclude the customer is not blocked here.
 * So the backend is named in the output, and a store that cannot outlive the process says so.
 */
class BlockList
{
    /**
     * Every IPv4 and IPv6 address, as two patterns.
     *
     * `find()` takes a pattern rather than offering an "everything" mode, and these are the
     * two ranges that mean everything. Listing is therefore two calls, which is also why a
     * single malformed pattern can never widen into a match-all: the caller has to ask.
     *
     * @var array<int, string>
     */
    private const EVERYTHING = ['0.0.0.0/0', '::/0'];

    private ?StorageInterface $storage = null;

    /**
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Configuration sources, as `Firewall::create()` takes them.
     */
    public function __construct(private readonly array $configs)
    {
    }

    /**
     * The configured storage backend, built once.
     *
     * @return StorageInterface
     *   The backend this configuration declares.
     */
    public function storage(): StorageInterface
    {
        if (!$this->storage instanceof StorageInterface) {
            $config = Config::load($this->configs);
            $storage = is_array($config['storage'] ?? null) ? $config['storage'] : [];

            $this->storage = StorageFactory::create($storage);
        }

        return $this->storage;
    }

    /**
     * What the backend is, and whether it can answer at all.
     *
     * @return array{class: string, queryable: bool, durable: bool}
     *   `queryable` is false for a backend that cannot enumerate its own keys --
     *   the Memcached example in the custom-storage guide cannot, which is why
     *   enumeration is a separate interface. `durable` is false for a store that
     *   dies with the process, where every answer here is truthfully empty and
     *   completely misleading.
     */
    public function backend(): array
    {
        $storage = $this->storage();

        return [
            'class' => $storage::class,
            'queryable' => $storage instanceof QueryableStorageInterface,
            // The exact class, not `instanceof`: FileStorage extends
            // InMemoryStorage and is perfectly durable.
            'durable' => $storage::class !== InMemoryStorage::class,
        ];
    }

    /**
     * Blocks matching an address or range.
     *
     * @param string $pattern
     *   An address or CIDR range.
     *
     * @return array<string, array<string, mixed>>
     *   Matching records, keyed by address. Expired-but-uncollected records are
     *   excluded by the backend, so this is what is actually in force.
     */
    public function find(string $pattern): array
    {
        $storage = $this->storage();

        if (!$storage instanceof QueryableStorageInterface) {
            return [];
        }

        return $storage->find($pattern);
    }

    /**
     * Every block currently in force.
     *
     * @return array<string, array<string, mixed>>
     *   Records keyed by address.
     */
    public function all(): array
    {
        $found = [];

        foreach (self::EVERYTHING as $pattern) {
            foreach ($this->find($pattern) as $address => $record) {
                $found[$address] = $record;
            }
        }

        return $found;
    }

    /**
     * Lift every block matching any of the given patterns.
     *
     * @param array<int, string> $patterns
     *   Addresses and/or ranges.
     *
     * @return int
     *   How many records were removed. Zero is not an error -- a block that had
     *   already lapsed is a block nobody needs lifted.
     */
    public function lift(array $patterns): int
    {
        $storage = $this->storage();

        if (!$storage instanceof QueryableStorageInterface) {
            return 0;
        }

        return $storage->deleteMatching($patterns);
    }

    /**
     * When an address offended, most recent first.
     *
     * Twelve offenses in a minute and twelve over a year are very different
     * clients, and the count alone cannot tell them apart.
     *
     * @param string $address
     *   The client address, which is also the storage key: `getKey()` stores it
     *   verbatim rather than hashing it, which is what makes range matching
     *   possible at all.
     * @param int $limit
     *   The most to return.
     *
     * @return array<int, int>
     *   Unix timestamps.
     */
    public function offenses(string $address, int $limit = 20): array
    {
        $storage = $this->storage();

        if (!$storage instanceof QueryableStorageInterface) {
            return [];
        }

        return $storage->listOffenses($address, 0, PHP_INT_MAX, $limit);
    }
}
