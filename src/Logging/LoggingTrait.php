<?php

namespace Kanopi\Firewall\Logging;

use Monolog\Logger;

/**
 * Trait for logging items.
 */
trait LoggingTrait
{
    /**
     * Log an Item.
     *
     * @param 'emergency'|'alert'|'critical'|'error'|'warning'|'notice'|'info'|'debug' $level
     *   Level to log.
     * @param string $message
     *   Message to send.
     * @param array<string, mixed> $context
     *   Context elements to send to the logger.
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        LoggingFactory::logger()->log($level, $message, $context);
    }

    /**
     * Return the Logger element.
     *
     * @return Logger
     *   Logger object.
     */
    protected function getLogger(): Logger
    {
        return LoggingFactory::logger();
    }
}
