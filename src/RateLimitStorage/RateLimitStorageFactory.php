<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Kanopi\Firewall\Logging\LoggingFactory;

/**
 * In charge of creating the Rate Limiting Storage objects.
 */
class RateLimitStorageFactory
{
    /**
     * Generate a new Storage element to get data from.
     *
     * @param class-string|RateLimitStorageInterface|null $type
     *   Class of the storage type to load.
     * @param array $config
     *   Configuration for the storage element.
     *
     * @return RateLimitStorageInterface
     *   Return the newly created object.
     */
    public static function create(string|RateLimitStorageInterface $type = null, array $config = []): RateLimitStorageInterface
    {
        $requestedType = $type;

        // If the provided storage is not valid default to InMemoryStorage.
        if (is_null($type) || (!is_object($type) && !class_exists($type)) || !in_array(RateLimitStorageInterface::class, class_implements($type), true)) {
            $type = InMemoryRateLimitStorage::class;

            LoggingFactory::logMessage('info', 'Rate limit storage type defaulted to InMemoryRateLimitStorage', [
                'requested_type' => is_object($requestedType) ? $requestedType::class : $requestedType,
                'reason' => is_null($requestedType) ? 'null' : (!is_object($requestedType) && !class_exists($requestedType) ? 'class_not_found' : 'invalid_interface'),
            ]);
        }

        if (is_object($type) && in_array(RateLimitStorageInterface::class, class_implements($type), true)) {
            LoggingFactory::logMessage('debug', 'Using existing rate limit storage instance', [
                'type' => $type::class,
            ]);
            return $type;
        }

        $storage = new $type($config);

        LoggingFactory::logMessage('debug', 'Rate limit storage created', [
            'type' => $type,
            'config_keys' => array_keys($config),
        ]);

        /** @phpstan-ignore return.type */
        return $storage;
    }
}
