<?php

namespace Kanopi\Firewall\Storage;

/**
 * In charge of creating the storage objects.
 */
class StorageFactory
{
    /**
     * Generate a new Storage element to get data from.
     *
     * @param array{type?: class-string|null, config?: array<string, mixed>} $config
     *   Configuration for the storage element.
     *
     * @return \Kanopi\Firewall\Storage\StorageInterface
     *   Return the newly created object.
     */
    public static function create(array $config = []): StorageInterface
    {
        $type = $config['type'] ?? null;
        $config = $config['config'] ?? [];
        // If the provided storage is not valid default to InMemoryStorage.
        if (!is_string($type) || !class_exists($type) || !in_array(StorageInterface::class, class_implements($type), true)) {
            $type = InMemoryStorage::class;
        }

        /** @var StorageInterface $storage */
        $storage = new $type($config);
        return $storage;
    }
}
