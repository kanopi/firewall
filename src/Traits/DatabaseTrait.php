<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Tools\DsnParser;
use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Database Trait used for referencing database.
 */
trait DatabaseTrait
{
    use LoggingTrait;

    protected Connection $connection;

    /** @phpstan-ignore-next-line */
    protected AbstractSchemaManager $schemaManager;

    /**
     * Create the Connection.
     */
    protected function createConnection(array|Connection $connectionParams): void
    {
        try {
            if ($connectionParams instanceof Connection) {
                $this->connection = $connectionParams;

                $this->getLogger()->debug('Using existing database connection');
            } else {
                if (isset($connectionParams['dsn'])) {
                    $dsnParser = new DsnParser();
                    $parsedParams = $dsnParser->parse($connectionParams['dsn']);

                    $this->getLogger()->debug('Parsed DSN for database connection', [
                        'driver' => $parsedParams['driver'] ?? 'unknown',
                    ]);

                    $connectionParams = $parsedParams;
                }

                $this->connection = DriverManager::getConnection($connectionParams);

                $this->getLogger()->debug('Database connection created', [
                    'driver' => $connectionParams['driver'] ?? 'unknown',
                ]);
            }

            $this->schemaManager = $this->connection->createSchemaManager();
            $this->createTable();
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to create database connection', [
                'error' => $exception->getMessage(),
            ]);
        }
    }

    /**
     * Create the table for storage.
     *
     * @throws \Doctrine\DBAL\Exception
     *   If there is an issue with creating the table an exception is thrown.
     */
    protected function createTable(): void
    {
        $tables = [];
        /** @phpstan-ignore-next-line */
        if (method_exists($this, 'getStorageTable') && !$this->schemaManager->tableExists($this->config['storage_table'])) {
            /** @var Table $table */
            $tables[] = $this->getStorageTable();
        } else {
            $this->getLogger()->debug('Database table already exists', [
                'table' => $this->config['storage_table'],
            ]);
        }

        /** @phpstan-ignore-next-line */
        if (method_exists($this, 'getOffenseStorageTable') && !$this->schemaManager->tableExists($this->config['offense_table'])) {
            /** @var Table $table */
            $tables[] = $this->getOffenseStorageTable();
        } else {
            $this->getLogger()->debug('Database table already exists', [
                'offense_table' => $this->config['offense_table'],
            ]);
        }

        foreach ($tables as $table) {
            try {
                $this->schemaManager->createTable($table);

                $this->getLogger()->info('Database table created', [
                    'table' => $table->getName(),
                ]);
            } catch (\Exception $e) {
                $this->getLogger()->error('Failed to create database table', [
                    'table' => $table->getName(),
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Enforce that the data being put into the database actually has columns for it.
     *
     * @param string $table
     *   Table name to get columns for.
     * @param array $data
     *   Data going into the table.
     *
     * @return array
     *   Data modified with values allowed in the table.
     */
    protected function enforceTableData(string $table, array $data = []): array
    {
        try {
            $columns = $this->schemaManager->listTableColumns($table);
            $removedKeys = [];

            foreach (array_keys($data) as $key) {
                if (!isset($columns[$key])) {
                    unset($data[$key]);
                    $removedKeys[] = $key;
                }
            }

            if ($removedKeys !== []) {
                $this->getLogger()->debug('Removed non-existent columns from data', [
                    'table' => $table,
                    'removed_keys' => $removedKeys,
                ]);
            }
        } catch (\Exception $exception) {
            $this->getLogger()->error('Failed to enforce table data', [
                'table' => $table,
                'error' => $exception->getMessage(),
            ]);
            return [];
        }

        return $data;
    }
}
