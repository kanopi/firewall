<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * In charge of creating the storage objects.
 */
class StorageFactory
{
    use LoggingTrait;

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
        $requestedType = $config['type'] ?? null;
        $storageConfig = $config['config'] ?? [];
        $type = $requestedType;

        // If the provided storage is not valid default to InMemoryStorage.
        if (!is_string($type) || !class_exists($type) || !in_array(StorageInterface::class, class_implements($type), true)) {
            $type = InMemoryStorage::class;

            LoggingFactory::logMessage('info', 'Storage type defaulted to InMemoryStorage', [
                'requested_type' => $requestedType,
                'reason' => is_string($requestedType) ? (!class_exists($requestedType) ? 'class_not_found' : 'invalid_interface') : ('not_string'),
            ]);
        }

        /** @var StorageInterface $storage */
        $storage = new $type($storageConfig);

        LoggingFactory::logMessage('debug', 'Storage created', [
            'type' => $type,
            'config_keys' => array_keys($storageConfig),
        ]);

        return $storage;
    }
}
