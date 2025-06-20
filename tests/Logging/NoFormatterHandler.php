<?php

namespace Kanopi\Firewall\Tests\Logging;

use Monolog\Handler\HandlerInterface;
use Monolog\LogRecord;

/**
 * A handler that does not support setFormatter.
 */
class NoFormatterHandler implements HandlerInterface
{
    public function handle(LogRecord $record): bool
    {
        return false;
    }

    public function isHandling(array|LogRecord $record): bool
    {
        return true;
    }

    public function handleBatch(array $records): void {}

    /**
     * @inheritDoc
     */
    public function close(): void {}
}
