<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

/**
 * In charge of creating the Rate Limiting Storage objects.
 */
class RateLimitStorageFactory
{
    /**
     * Generate a new Storage element to get data from.
     *
     * @param class-string|null $type
     *   Class of the storage type to load.
     * @param array $config
     *   Configuration for the storage element.
     *
     * @return RateLimitStorageInterface
     *   Return the newly created object.
     */
    public static function create(?string $type = null, array $config = []): RateLimitStorageInterface
    {
        // If the provided storage is not valid default to InMemoryStorage.
        if (is_null($type) || !class_exists($type) || !class_implements($type, RateLimitStorageInterface::class)) {
            $type = InMemoryRateLimitStorage::class;
        }

        /** @var RateLimitStorageInterface $obj */
        $obj = new $type($config);

        return $obj;
    }
}
