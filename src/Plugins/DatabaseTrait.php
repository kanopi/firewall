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

/**
 * Database Trait used for referencing database.
 */
trait DatabaseTrait
{
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
            } else {
                if (isset($connectionParams['dsn'])) {
                    $dsnParser = new DsnParser();
                    $connectionParams = $dsnParser->parse($connectionParams['dsn']);
                }

                $this->connection = DriverManager::getConnection($connectionParams);
            }
            $this->schemaManager = $this->connection->createSchemaManager();
            $this->createTable();
        } catch (\Exception) {
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
        /** @phpstan-ignore-next-line */
        if (method_exists($this, 'getStorageTable') && !$this->schemaManager->tableExists($this->config['storage_table'])) {
            /** @var Table $table */
            $table = $this->getStorageTable();
            try {
                $this->schemaManager->createTable($table);
            } catch (\Exception) {
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
            foreach ($data AS $key => $value) {
                if (!isset($columns[$key])) {
                    unset($data[$key]);
                }
            }
        } catch (\Exception) {
            return [];
        }

        return $data;
    }
}
