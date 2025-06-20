<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\RateLimitStorage;

use Kanopi\Firewall\Logging\LoggingTrait;

/**
 * Abstract base class for rate limit storage.
 */
abstract class AbstractRateLimitStorage implements RateLimitStorageInterface
{
    use LoggingTrait;

    /**
     * Constructor.
     *
     * @param array $config
     *   Configuration options.
     */
    public function __construct(protected array $config = [])
    {
    }
}
