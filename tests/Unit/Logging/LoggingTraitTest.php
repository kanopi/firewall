<?php

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\LoggingTraitUser;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\TestHandler;
use PHPUnit\Framework\TestCase;

/**
 * Test the LoggingTrait in isolation.
 */
final class LoggingTraitTest extends TestCase
{

    /**
     * Ensures any class using LoggingTrait can send messages to the configured logger.
     */
    public function testTraitLogsMessage(): void
    {
        $testHandler = new TestHandler();
        $logger = new Logger('test-trait');
        $logger->pushHandler($testHandler);

        LoggingFactory::setLogger($logger);

        $user = new LoggingTraitUser();
        $user->logSomething();

        $this->assertTrue($testHandler->hasWarningRecords());
        $this->assertTrue($testHandler->hasRecordThatContains('Trait-based warning log', Level::Warning));
    }
}