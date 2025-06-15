<?php

namespace Kanopi\Firewall\Exception;

/**
 * Block Access Exception thrown.
 */
class BlockAccessException extends \Exception
{
    /**
     * Constructs a new BlockAccessException Object.
     */
    public function __construct(string $message = "Banned", int $code = 406, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
