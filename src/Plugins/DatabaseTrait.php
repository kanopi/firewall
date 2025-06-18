<?php

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

    protected AbstractSchemaManager $schemaManager;

    /**
     * Create the Connection.
     */
    protected function createConnection(array $connectionParams): void
    {
        try {
            if (isset($connectionParams['dsn'])) {
                $dsnParser = new DsnParser();
                $connectionParams = $dsnParser->parse($connectionParams['dsn']);
            }

            $this->connection = DriverManager::getConnection($connectionParams);
            $this->schemaManager = $this->connection->createSchemaManager();
            $this->createTable();
        } catch (\Exception) {}
    }

    /**
     * Create the table for storage.
     *
     * @throws \Doctrine\DBAL\Exception
     *   If there is an issue with creating the table an exception is thrown.
     */
    protected function createTable(): void
    {
        if (method_exists($this, 'getStorageTable')) {
            if (!$this->schemaManager->tableExists($this->config['storage_table'])) {
                /** @var Table $table */
                $table = $this->getStorageTable();
                try {
                    $this->schemaManager->createTable($table);
                } catch (\Exception) {}
            }
        }
    }

}