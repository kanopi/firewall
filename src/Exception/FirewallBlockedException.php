<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

/**
 * Exception thrown when the firewall blocks a request in exception mode.
 */
class FirewallBlockedException extends \RuntimeException
{
    /**
     * Constructs a new FirewallBlockedException object.
     */
    public function __construct(string $message, int $statusCode = 400, ?\Throwable $previous = null)
    {
        parent::__construct($message, $statusCode, $previous);
    }

    /**
     * Get the HTTP status code associated with this block.
     */
    public function getStatusCode(): int
    {
        return $this->getCode();
    }
}
