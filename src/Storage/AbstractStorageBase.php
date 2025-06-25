<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Abstract Class for Storage Base.
 */
abstract class AbstractStorageBase implements StorageInterface
{
    use LoggingTrait;

    /**
     * Construct a new AbstractStorageBase object.
     *
     * @param array<string, mixed> $config
     *   Configuration details.
     */
    public function __construct(protected array $config = [])
    {
        $this->getLogger()->debug('Storage initialized', [
            'storage_type' => static::class,
            'config' => array_keys($config),
        ]);
    }
}
