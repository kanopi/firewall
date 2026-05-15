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
     * Check if an error-or-higher message containing the given string was logged.
     */
    public function hasErrorContaining(string $needle): bool
    {
        return $this->hasRecordAtLevelContaining(400, $needle);
    }

    /**
     * Check if a warning-level message containing the given string was logged.
     */
    public function hasWarningContaining(string $needle): bool
    {
        foreach ($this->records as $record) {
            if (
                $record->level->value >= 300
                && $record->level->value < 400
                && str_contains((string)$record->message, $needle)
            ) {
                return true;
            }
        }
        return false;
    }

    private function hasRecordAtLevelContaining(int $minLevel, string $needle): bool
    {
        foreach ($this->records as $record) {
            if ($record->level->value >= $minLevel && str_contains((string)$record->message, $needle)) {
                return true;
            }
        }
        return false;
    }
}
