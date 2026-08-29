<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Traits\AddressMatchTrait;
use Kanopi\Firewall\Traits\DatabaseTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Connection to Database Storage related items.
 */
class DatabaseStorage extends AbstractStorageBase implements QueryableStorageInterface
{
    use AddressMatchTrait;
    use DatabaseTrait;

    /**
     * Constructs a new DatabaseStorage Object.
     *
     * @param array<string, mixed> $config
     *   Storage configuration, including the `connection` parameters.
     *
     * @throws \Kanopi\Firewall\Exception\StorageConnectionException
     *   When the database cannot be reached or its schema cannot be prepared.
     *   Construction fails loudly rather than handing back an object whose
     *   first query dies on an uninitialized property (#144), matching how
     *   `FileStorage` already refuses a backing file it cannot use.
     */
    public function __construct(array $config)
    {
        if (is_array($config['connection']) && isset($config['connection']['port']) && is_numeric($config['connection']['port'])) {
            $config['connection']['port'] = intval($config['connection']['port']);
        }

        parent::__construct($config);
        $this->config['storage_table'] ??= 'firewall_storage';
        $this->config['offenses_table'] ??= 'firewall_offenses';

        $this->createConnection($config['connection'] ?? []);
        $this->getLogger()->info('Database storage initialized', [
            'storage_table' => $this->config['storage_table'],
            'offenses_table' => $this->config['offenses_table'],
        ]);
    }

    /**
     * Get the storage table.
     */
    protected function getStorageTables(): array
    {
        return [
            new Table(
                $this->config['storage_table'],
                [
                    new Column('remote_address', Type::getType('string'), ['length' => 255]),
                    new Column('plugin', Type::getType('string'), ['length' => 255]),
                    new Column('event_id', Type::getType('string'), ['length' => 255]),
                    new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
                    new Column('request', Type::getType('text')),
                    new Column('expire', Type::getType('integer'), ['unsigned' => true, 'length' => 10, 'default' => 0]),
                    new Column('metadata', Type::getType('text'))
                ], // Columns.
                [
                    new Index('remote_address', ['remote_address'], true, true),
                ], // Indexes.
            ),
            new Table(
                $this->config['offenses_table'],
                [
                    new Column('id', Type::getType('integer'), ['autoincrement' => true]),
                    new Column('remote_address', Type::getType('string'), ['length' => 255]),
                    new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
                ],
                [
                    new Index('idx', ['id'], true, true),
                    new Index('remote_address_x', ['remote_address'], false, false),
                ]
            )
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function recordOffense(string $key): bool
    {
        try {
            $this->connection->insert($this->config['offenses_table'], [
                'remote_address' => $key,
                'timestamp' => strtotime(date('c')),
            ]);
            $this->getLogger()->debug('Recorded offense', [
                'remote_address' => $key,
                'timestamp' => date('c'),
            ]);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to record offense', [
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, array $value, int $expire = 0): bool
    {
        // Read before the try, so the tail of this method cannot see it undefined.
        $isBlockRecord = isset($value['request']);

        try {
            // Pre-fix this used `@serialize(...)`, so any future caller who
            // unserialize()'d the column would have a CWE-502 PHP Object
            // Injection sink fed by the row's content. `serializeRequest()`
            // returns a plain array (scalars + nested arrays + headers/
            // cookies bags pre-flattened to arrays), which JSON round-trips
            // cleanly. The `@` is dropped — json_encode failures should be
            // logged and abort the write rather than store a "false" string
            // silently.
            //
            // `set()` is the interface's general key/value write, not only the
            // block-record writer, and this implementation used to assume otherwise.
            // `Firewall::consumeSingleUseSolution()` stores `['consumed_at' => ...]`
            // through it to make a solved challenge single-use, and that value has no
            // request, no timestamp, no plugin and no event id.
            //
            // Measured on a site using database storage: reading those keys
            // unconditionally emitted two PHP warnings, and with `display_errors` on
            // they were written into the challenge endpoint's response *ahead of its
            // JSON body*, so the browser's JSON.parse() failed and the interstitial
            // reported "Verification failed" on a challenge the visitor had in fact
            // just passed. The insert then failed anyway on `plugin`, which is NOT
            // NULL with no default, so `set()` returned FALSE and stored nothing --
            // the replay guard recorded no solution and a solved token stayed
            // replayable until it expired. `InMemoryStorage` and `FileStorage` store
            // the array as given and had neither problem.
            //
            // The defaults are supplied here rather than added to the schema because
            // `getStorageTables()` only runs when the table is missing, so a column
            // default would not reach any installation already carrying this table.
            $value['request'] = json_encode(
                $value['request'] ?? null,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
            );

            // Accepts what the block path sends (an ISO-8601 string from
            // `getStorageData()`), a Unix timestamp, or nothing at all. A failed parse
            // used to store 0, which reads back as 1970.
            $timestamp = $value['timestamp'] ?? null;
            $value['timestamp'] = is_numeric($timestamp)
                ? (int) $timestamp
                : (strtotime((string) $timestamp) ?: time());

            // Both are NOT NULL in `getStorageTables()`.
            $value['plugin'] ??= '';
            $value['event_id'] ??= '';

            $data = array_merge(
                $value,
                [
                    'remote_address' => $key,
                    'expire' => $expire > 0 ? time() + $expire : $expire,
                ]
            );
            $data['metadata'] = json_encode($data);
            $data = $this->enforceTableData($this->config['storage_table'], $data);
            if ($this->exists($key)) {
                $this->connection->update(
                    $this->config['storage_table'],
                    $data,
                    [
                        'remote_address' => $key,
                    ]
                );
                $this->getLogger()->debug('Updated existing entry in database storage', [
                    'key' => $key,
                    'table' => $this->config['storage_table'],
                    'expire' => $expire,
                ]);
            } else {
                $this->connection->insert($this->config['storage_table'], $data);
                $this->getLogger()->debug('Inserted new entry in database storage', [
                    'key' => $key,
                    'table' => $this->config['storage_table'],
                    'expire' => $expire,
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to set value in database storage', [
                'key' => $key,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        // Only for an actual block. The offenses table drives repeat-offender
        // escalation and is never pruned, so counting a consumed challenge solution
        // as an offense would file a permanent row under a key that is a hash rather
        // than an address, growing the table once per solved challenge, forever.
        if ($isBlockRecord) {
            $this->recordOffense($key);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        try {
            $affected = $this->connection->delete($this->config['storage_table'], [
                'remote_address' => $key,
            ]);

            if ($affected > 0) {
                $this->getLogger()->debug('Deleted entry from database storage', [
                    'key' => $key,
                    'table' => $this->config['storage_table'],
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to delete from database storage', [
                'key' => $key,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if ($this->exists($key)) {
            try {
                $count = $this->connection->createQueryBuilder()
                    ->select('*')
                    ->from($this->config['storage_table'])
                    ->where('remote_address = :remote_address')
                    ->setParameter('remote_address', $key)
                    ->executeQuery();
                return $count->fetchAssociative();
            } catch (\Exception $exception) {
                $this->getLogger()->error('Failed to get entry from database storage', [
                    'table' => $this->config['storage_table'],
                    'key' => $key,
                    'error' => $exception->getMessage(),
                ]);
            }
        }

        return $default;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        try {
            $affected = $this->connection->delete($this->config['storage_table']);
            $this->getLogger()->info('Database storage reset', [
                'table' => $this->config['storage_table'],
                'entries_cleared' => $affected,
            ]);
            return true;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to reset database storage', [
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        try {
            $results = $this->connection->createQueryBuilder()
                ->select('remote_address')
                ->from($this->config['storage_table'])
                ->where('remote_address = :remote_address')
                ->setParameter('remote_address', $key)
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to check if key exists', [
                'table' => $this->config['storage_table'],
                'key' => $key,
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        return $results !== [];
    }

    /**
     * {@inheritdoc}
     */
    public function expire(): bool
    {
        try {
            $result = $this->connection->createQueryBuilder()
                ->delete($this->config['storage_table'])
                ->where('expire < :expire AND expire > 0')
                ->setParameter('expire', time())
                ->executeQuery();

            $affected = $result->rowCount();
            if ($affected > 0) {
                $this->getLogger()->debug('Cleared expired entries from database storage', [
                    'table' => $this->config['storage_table'],
                    'entries_cleared' => $affected,
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to clear expired entries', [
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function addToExpire(string $key, int $amount): bool
    {
        try {
            // Pre-fix this string-concatenated a `' u'` alias onto the
            // table name to satisfy `u.expire` qualified column references
            // and carried a phpstan-ignore comment to mask the type
            // complaint. That route bypasses DBAL's identifier-quoting
            // path, which is fine for the safe table names we ship but
            // breaks on reserved words, schema-qualified names, or any
            // identifier that needs quoting. DBAL handles unqualified
            // column names in `set()` and `where()` without the alias.
            $result = $this->connection->createQueryBuilder()
                ->update($this->config['storage_table'])
                ->set('expire', 'expire + :expire')
                ->where('remote_address = :remote_address')
                ->andWhere('expire > 0')
                ->setParameter('remote_address', $key)
                ->setParameter('expire', $amount)
                ->executeQuery()
                ->fetchAllAssociative();

            if ($result !== []) {
                $this->getLogger()->debug('Extended expiration time', [
                    'key' => $key,
                    'table' => $this->config['storage_table'],
                    'additional_seconds' => $amount,
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to extend expiration', [
                'key' => $key,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        try {
            $results = $this->connection->createQueryBuilder()
                ->select('remote_address')
                ->from($this->config['offenses_table'])
                ->where('remote_address = :remote_address')
                ->andWhere('timestamp >= :start AND timestamp <= :end')
                ->setParameter('remote_address', $key)
                ->setParameter('start', $start)
                ->setParameter('end', $end)
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (\Exception) {
            return 0;
        }

        return count($results);
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $pattern): array
    {
        if (!$this->isValidPattern($pattern)) {
            $this->getLogger()->warning('Storage find skipped - not a valid address or CIDR range', [
                'pattern' => $pattern,
            ]);
            return [];
        }

        $now = time();

        try {
            $builder = $this->connection->createQueryBuilder()
                ->select('*')
                ->from($this->config['storage_table'])
                // Lapsed-but-uncollected rows are excluded here rather than in
                // PHP so the database does the filtering it is good at, and so
                // an operator is never shown a block that is no longer in force.
                ->where('expire = 0 OR expire >= :now')
                ->setParameter('now', $now);

            // A bare address is an indexed equality lookup — `remote_address`
            // carries a unique index, so this is a single row fetch rather
            // than a table scan. Only a CIDR range needs every candidate
            // pulled back for matching in PHP, because CIDR containment is not
            // portable SQL across MySQL, PostgreSQL and SQLite.
            if (!str_contains($pattern, '/')) {
                $builder->andWhere('remote_address = :remote_address')
                    ->setParameter('remote_address', $pattern);
            }

            $rows = $builder->executeQuery()->fetchAllAssociative();
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to search database storage', [
                'table' => $this->config['storage_table'],
                'pattern' => $pattern,
                'error' => $exception->getMessage(),
            ]);
            return [];
        }

        $matches = [];

        foreach ($rows as $row) {
            $address = (string) ($row['remote_address'] ?? '');
            if ($address === '') {
                continue;
            }

            if (!$this->addressMatches($address, $pattern)) {
                continue;
            }

            $expire = (int) ($row['expire'] ?? 0);

            $matches[$address] = [
                'value' => $row,
                'expire' => $expire,
                'expires_at' => $expire > 0 ? date('c', $expire) : null,
                'offenses' => $this->countOffenses($address),
            ];
        }

        $this->getLogger()->debug('Storage find completed', [
            'pattern' => $pattern,
            'candidates' => count($rows),
            'matches' => count($matches),
        ]);

        return $matches;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteMatching(array $patterns): int
    {
        $patterns = $this->validPatterns($patterns);

        if ($patterns === []) {
            return 0;
        }

        // Resolve every pattern to concrete addresses first, then delete by
        // exact key. Two reasons: CIDR containment has no portable SQL form
        // across the supported drivers, and deleting by resolved address keeps
        // the offense cleanup below operating on the same set the storage
        // delete did.
        $addresses = [];

        foreach ($patterns as $pattern) {
            if (!str_contains($pattern, '/')) {
                // Exact addresses do not need resolving. Taking them straight
                // through also means an un-block still works for a row whose
                // expiry has already lapsed, which find() deliberately hides.
                $addresses[$pattern] = true;
                continue;
            }

            try {
                $rows = $this->connection->createQueryBuilder()
                    ->select('remote_address')
                    ->from($this->config['storage_table'])
                    ->executeQuery()
                    ->fetchAllAssociative();
            } catch (\Exception $exception) {
                $this->getLogger()->error('Failed to resolve pattern against database storage', [
                    'table' => $this->config['storage_table'],
                    'pattern' => $pattern,
                    'error' => $exception->getMessage(),
                ]);
                continue;
            }

            foreach ($rows as $row) {
                $address = (string) ($row['remote_address'] ?? '');

                if ($address !== '' && $this->addressMatches($address, $pattern)) {
                    $addresses[$address] = true;
                }
            }
        }

        $deleted = 0;

        foreach (array_keys($addresses) as $address) {
            try {
                $affected = $this->connection->delete($this->config['storage_table'], [
                    'remote_address' => $address,
                ]);
            } catch (\Exception $exception) {
                $this->getLogger()->error('Failed to delete matched record from database storage', [
                    'table' => $this->config['storage_table'],
                    'address' => $address,
                    'error' => $exception->getMessage(),
                ]);
                continue;
            }

            if ($affected > 0) {
                $deleted++;
            }

            // Offenses are cleared alongside the block. Left behind, an
            // address an operator just un-blocked would be escalated straight
            // back to a longer ban by `blocking_escalation` on its next
            // offence, and the un-block would appear not to have worked.
            try {
                $this->connection->delete($this->config['offenses_table'], [
                    'remote_address' => $address,
                ]);
            } catch (\Exception $exception) {
                $this->getLogger()->warning('Deleted the block but failed to clear its offense history', [
                    'table' => $this->config['offenses_table'],
                    'address' => $address,
                    'error' => $exception->getMessage(),
                ]);
            }
        }

        $this->getLogger()->info('Storage records deleted by pattern', [
            'patterns' => $patterns,
            'deleted' => $deleted,
        ]);

        return $deleted;
    }
}
