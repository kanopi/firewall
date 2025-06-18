<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Storage;

use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Type;
use Kanopi\Firewall\Plugins\DatabaseTrait;

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
                new Column('remote_address', Type::getType('string'), ['length' => 255]),
                new Column('plugin', Type::getType('string'), ['length' => 255]),
                new Column('event_id', Type::getType('string'), ['length' => 255]),
                new Column('blocked', Type::getType('integer'), ['unsigned' => true, 'default' => 0]),
                new Column('request', Type::getType('text')),
                new Column('expire', Type::getType('integer'), ['unsigned' => true, 'length' => 10, 'default' => 0]),
            ], // Columns.
            [
                new Index('remote_address', ['remote_address'], true, true),
            ], // Indexes.
        );
    }

    /**
     * {@inheritdoc}
     */
    public function set(string $key, mixed $value, int $expire = 0): bool
    {
        try {
            $value['request'] = @serialize($value['request']);
            $value['blocked'] = strtotime($value['blocked']);
            $data = array_merge(
                is_array($value) ? $value : ['value' => $value],
                [
                    'remote_address' => $key,
                    'expire' => $expire > 0 ? time() + $expire : $expire,
                ]
            );
            if ($this->exists($key)) {
                $this->connection->update(
                    $this->config['storage_table'],
                    $data,
                    [
                        'remote_address' => $key,
                    ]
                );
            } else {
                $this->connection->insert($this->config['storage_table'], $data);
            }
        } catch (\Exception) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(string $key): bool
    {
        try {
            $this->connection->delete($this->config['storage_table'], [
                'remote_address' => $key,
            ]);
        } catch (\Exception) {
            return false;
        }
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key, mixed $default = null): mixed
    {
        try {
            if ($this->exists($key)) {
                $count = $this->connection->createQueryBuilder()
                    ->select('*')
                    ->from($this->config['storage_table'])
                    ->where('remote_address = :remote_address')
                    ->setParameter('remote_address', $key)
                    ->executeQuery();
                return $count->fetchAssociative();
            }
        } catch (\Exception) {
        }
        return $default;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): bool
    {
        try {
            $this->connection->delete($this->config['storage_table']);
            return true;
        } catch (\Exception) {
        }
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function exists(string $key): bool
    {
        try {
            $count = $this->connection->createQueryBuilder()
                ->select('remote_address')
                ->from($this->config['storage_table'])
                ->where('remote_address = :remote_address')
                ->setParameter('remote_address', $key)
                ->executeQuery();
        } catch (\Exception) {
            return false;
        }
        return $count->rowCount() > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function clearExpire(): bool
    {
        try {
            $this->connection->createQueryBuilder()
                ->delete($this->config['storage_table'])
                ->where('expire < :expire AND expire > 0')
                ->setParameter('expire', time())
                ->executeQuery();
        } catch (\Exception) {
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
            $this->connection->createQueryBuilder()
                /** @phpstan-ignore-next-line  */
                ->update($this->config['storage_table'] . ' u')
                ->set('u.expire', 'u.expire + :expire')
                ->where('remote_address = :remote_address')
                ->andWhere('u.expire > 0')
                ->setParameter('remote_address', $key)
                ->setParameter('expire', $amount)
                ->executeQuery();
        } catch (\Exception) {
            return false;
        }
        return true;
    }
}
