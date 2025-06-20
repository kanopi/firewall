<?php

namespace Kanopi\Firewall\Tests\Logging;

use Monolog\Handler\AbstractProcessingHandler;
use Monolog\LogRecord;

/**
 * Monolog handler to capture logs for assertions in tests.
 */
class TestLogHandler extends AbstractProcessingHandler
{
    public array $records = [];

    protected function write(LogRecord $record): void
    {
        $this->records[] = $record;
    }

    /**
     * Check if an error message containing the given string was logged.
     */
    public function hasErrorContaining(string $needle): bool
    {
        foreach ($this->records as $record) {
            if ($record->level->value >= 400 && str_contains((string)$record->message, $needle)) {
                return true;
            }
        }
        return false;
    }
}
