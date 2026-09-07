<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Traits\DatabaseTrait;

/**
 * Connection to Database Rate Limit Storage related items.
 */
class DatabaseRateLimitStorage extends AbstractRateLimitStorage implements PrunableRateLimitStorageInterface
{
    use DatabaseTrait;

    /**
     * Creates a new DatabaseRateLimitStorage object.
     *
     * @param array<string, mixed> $config
     *   Storage configuration, including the `connection` parameters.
     *
     * @throws \Kanopi\Firewall\Exception\StorageConnectionException
     *   When the database cannot be reached or its schema cannot be prepared
     *   (#144). The rate-limit plugin builds its storage lazily, so this
     *   surfaces on the first request the plugin evaluates.
     */
    public function __construct(array $config = [])
    {
        // Pre-fix this read `$config['connection']` unguarded, so a config
        // that declares none emitted `Undefined array key "connection"` on
        // every construction -- in front of the StorageConnectionException
        // that actually explains the problem. `DatabaseStorage` had already
        // fixed that for itself; sharing the normaliser is what finally
        // brought the fix here.
        $config['connection'] = self::normalizeConnectionParameters($config['connection'] ?? null) ?? [];

        parent::__construct($config);
        $this->config['storage_table'] ??= 'firewall_rate_limit_storage';

        $this->createConnection($config['connection']);
        $this->getLogger()->info('Database rate limit storage initialized', [
            'table' => $this->config['storage_table'],
            'driver' => $this->config['connection']['driver'] ?? 'unknown',
        ]);
    }

    /**
     * Return the storage table definition.
     */
    protected function getStorageTables(): array
    {
        // Read once into a local: the value comes from YAML, so it reaches
        // here as `mixed`, and the index name below is built from it.
        $table = (string) $this->config['storage_table'];

        return [
            new Table(
                $table,
                [
                    new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
                    new Column('rule', Type::getType('string'), ['length' => 255]),
                    new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'length' => 10, 'default' => 0]),
                ], // Columns.
                [
                    new Index('PRIMARY', ['id'], true, true),
                    // Every query this table serves is "this rule, this window":
                    // `countRequests()` and `forget()` both filter on `rule`
                    // and range over `timestamp`, and neither had an index to
                    // do it with, so both were full scans of a table that grew
                    // without bound (#183).
                    //
                    // `getStorageTables()` only runs when the table is absent,
                    // so an existing installation does not gain these. Adding
                    // them by hand is one statement per index and is worth
                    // doing:
                    //
                    //   CREATE INDEX firewall_rate_limit_storage_rule_window_idx
                    //     ON firewall_rate_limit_storage (rule, timestamp);
                    new Index($table . '_rule_window_idx', ['rule', 'timestamp']),
                ], // Indexes.
            )
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function recordRequest(string $key, int $timestamp): void
    {
        try {
            $this->connection->insert($this->config['storage_table'], [
                'rule' => $key,
                'timestamp' => $timestamp,
            ]);

            $this->getLogger()->debug('Rate limit request recorded', [
                'key' => $key,
                'timestamp' => $timestamp,
                'table' => $this->config['storage_table'],
            ]);
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to record rate limit request', [
                'key' => $key,
                'timestamp' => $timestamp,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function forget(string $key, int $before): int
    {
        try {
            $dropped = (int) $this->connection->createQueryBuilder()
                ->delete($this->config['storage_table'])
                ->where('rule = :rule')
                ->andWhere('timestamp < :before')
                ->setParameter('rule', $key)
                // Clamped for the same reason the offense queries are: the
                // column is `Type::getType('integer')`, which PostgreSQL
                // creates as a 4-byte `INT` and refuses to compare against a
                // value outside that range.
                ->setParameter('before', self::clampTimestampBound($before))
                ->executeStatement();
        } catch (\Exception $exception) {
            // Housekeeping. A rate limit that still counts correctly against a
            // table it could not tidy is working, so this is reported and the
            // request carries on.
            $this->getLogger()->error('Failed to drop rate limit records outside the window', [
                'key' => $key,
                'before' => $before,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);

            return 0;
        }

        if ($dropped > 0) {
            $this->getLogger()->debug('Dropped rate limit records outside the window', [
                'key' => $key,
                'before' => $before,
                'dropped' => $dropped,
                'table' => $this->config['storage_table'],
            ]);
        }

        return $dropped;
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        try {
            // Counted by the database. Pre-fix this fetched every row in the
            // window and counted them in PHP -- on the rate limiter's
            // per-request path, so the client generating the most rows paid
            // to have all of them sent back on every one of its requests.
            $count = $this->countRows(
                $this
                    ->connection
                    ->createQueryBuilder()
                    ->from($this->config['storage_table'])
                    ->where('rule = :rule')
                    ->andWhere('timestamp >= :start')
                    ->andWhere('timestamp <= :end')
                    ->setParameter('rule', $key)
                    ->setParameter('start', $start)
                    ->setParameter('end', $end)
            );

            $this->getLogger()->debug('Rate limit request count', [
                'key' => $key,
                'start' => $start,
                'end' => $end,
                'count' => $count,
                'table' => $this->config['storage_table'],
            ]);

            return $count;
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to count rate limit requests', [
                'key' => $key,
                'start' => $start,
                'end' => $end,
                'table' => $this->config['storage_table'],
                'error' => $exception->getMessage(),
            ]);
            return 0;
        }
    }
}
