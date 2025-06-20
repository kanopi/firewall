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
use Kanopi\Firewall\Plugins\DatabaseTrait;

/**
 * Connection to Database Rate Limit Storage related items.
 */
class DatabaseRateLimitStorage extends AbstractRateLimitStorage
{
    use DatabaseTrait;

    /**
     * Creates a new DatabaseRateLimitStorage object.
     */
    public function __construct(array $config = [])
    {
        parent::__construct($config);
        $this->config['storage_table'] ??= 'firewall_rate_limit_storage';
        $this->createConnection($config['connection'] ?? []);
    }

    /**
     * Create the storage table.
     */
    protected function getStorageTable(): Table
    {
        return new Table(
            $this->config['storage_table'],
            [
                new Column('id', Type::getType('integer'), ['autoincrement' => true, 'unsigned' => true]),
                new Column('rule', Type::getType('string'), ['length' => 255]),
                new Column('timestamp', Type::getType('integer'), ['unsigned' => true, 'length' => 10, 'default' => 0]),
            ], // Columns.
            [
                new Index('PRIMARY', ['id'], true, true),
            ], // Indexes.
        );
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
        } catch (\Exception) {
        }
    }

    /**
     * {@inheritdoc}
     */
    public function countRequests(string $key, int $start, int $end): int
    {
        try {
            return count($this
                ->connection
                ->createQueryBuilder()
                ->select('*')
                ->from($this->config['storage_table'])
                ->where('rule = :rule')
                ->andWhere('timestamp >= :start')
                ->andWhere('timestamp <= :end')
                ->setParameter('rule', $key)
                ->setParameter('start', $start)
                ->setParameter('end', $end)
                ->executeQuery()
                ->fetchAllAssociative());
        } catch (\Exception) {
            return 0;
        }
    }
}
