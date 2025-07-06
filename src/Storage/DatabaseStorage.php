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
use Kanopi\Firewall\Traits\DatabaseTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Connection to Database Storage related items.
 */
class DatabaseStorage extends AbstractStorageBase
{
    use DatabaseTrait;

    /**
     * Constructs a new DatabaseStorage Object.
     */
    public function __construct(array $config)
    {
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
    public function recordOffense(Request $request): bool
    {
        try {
            $this->connection->insert($this->config['offenses_table'], [
                'remote_address' => $request->getClientIp(),
                'timestamp' => strtotime(date('c')),
            ]);
            $this->getLogger()->debug('Recorded offense', [
                'remote_address' => $request->getClientIp(),
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
    public function set(Request $request, int $expire = 0): bool
    {
        $key = $request->getClientIp();
        $plugin = $request->attributes->get('blocking-plugin');
        $value = $this->getBlockingData($request, $plugin);
        try {
            $value['request'] = @serialize($value['request']);
            $value['timestamp'] = strtotime((string) $value['timestamp']);
            $data = array_merge(
                $value,
                [
                    'remote_address' => $key,
                    'expire' => $expire > 0 ? time() + $expire : $expire,
                ]
            );
            $data['metadata'] = json_encode($data);
            $data = $this->enforceTableData($this->config['storage_table'], $data);
            if ($this->exists($request)) {
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

        $this->recordOffense($request);
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(Request $request): bool
    {
        $key = $request->getClientIp();
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
    public function get(Request $request, mixed $default = null): mixed
    {
        $key = $request->getClientIp();
        if ($this->exists($request)) {
            try {
                $count = $this->connection->createQueryBuilder()
                    ->select('*')
                    ->from($this->config['storage_table'])
                    ->where('remote_address = :remote_address')
                    ->setParameter('remote_address', $key)
                    ->executeQuery();
                return $count->fetchAssociative();
            } catch (\Exception) {
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
    public function exists(Request $request): bool
    {
        $key = $request->getClientIp();
        try {
            $results = $this->connection->createQueryBuilder()
                ->select('remote_address')
                ->from($this->config['storage_table'])
                ->where('remote_address = :remote_address')
                ->setParameter('remote_address', $key)
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (\Exception) {
            return false;
        }

        return $results !== [];
    }

    /**
     * {@inheritdoc}
     */
    public function clearExpire(): bool
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
    public function addToExpire(Request $request, int $amount): bool
    {
        $key = $request->getClientIp();
        try {
            $result = $this->connection->createQueryBuilder()
                /** @phpstan-ignore-next-line  */
                ->update($this->config['storage_table'] . ' u')
                ->set('u.expire', 'u.expire + :expire')
                ->where('remote_address = :remote_address')
                ->andWhere('u.expire > 0')
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
    public function countOffenses(Request $request, int $start = 0, int $end = PHP_INT_MAX): int
    {
        $key = $request->getClientIp();
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
}
