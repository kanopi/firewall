<?php

namespace Kanopi\Firewall\Tests\Storage;

use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * Fake custom storage implementation for testing StorageFactory.
 */
class FakeCustomStorage extends InMemoryStorage
{
    /**
     * Returns the configuration passed to the constructor.
     */
    public function getConfig(): array
    {
        return $this->config;
    }
}
