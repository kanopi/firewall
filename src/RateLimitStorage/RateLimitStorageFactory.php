<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

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
        // If the provided storage is not valid default to InMemoryStorage.
        if (is_null($type) || (!is_object($type) && !class_exists($type)) || !in_array(RateLimitStorageInterface::class, class_implements($type), true)) {
            $type = InMemoryRateLimitStorage::class;
        }

        if (is_object($type) && in_array(RateLimitStorageInterface::class, class_implements($type), true)) {
            return $type;
        }

        /** @phpstan-ignore return.type */
        return new $type($config);
    }
}
