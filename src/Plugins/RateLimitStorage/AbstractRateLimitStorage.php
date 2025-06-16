<?php

namespace Kanopi\Firewall\Plugins\RateLimitStorage;

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
