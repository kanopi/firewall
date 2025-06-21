<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Logging;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Tests\Logging\NoFormatterHandler;
use Monolog\Handler\TestHandler;
use Monolog\Formatter\LineFormatter;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the LoggingFactory class.
 */
final class LoggingFactoryTest extends TestCase
{
    /**
     * Reset static state between tests.
     */
    protected function tearDown(): void
    {
        $ref = new \ReflectionClass(LoggingFactory::class);
        $prop = $ref->getProperty('logger');
        $prop->setAccessible(true);
        $prop->setValue(null);
    }

    /**
     * Tests that LoggingFactory::create returns a Logger with the correct channel and handler.
     */
    public function testCreateReturnsLoggerWithHandler(): void
    {
        $logger = LoggingFactory::create([
            [
                'class' => TestHandler::class,
                'args' => [],
            ],
        ], 'custom_channel');

        $this->assertInstanceOf(Logger::class, $logger);
        $this->assertSame('custom_channel', $logger->getName());

        $handlers = $logger->getHandlers();
        $this->assertCount(1, $handlers);
        $this->assertInstanceOf(TestHandler::class, $handlers[0]);
    }

    /**
     * Tests that LoggingFactory::create converts Monolog level string to Level object.
     */
    public function testCreateConvertsLevelStringToLevelObject(): void
    {
        $logger = LoggingFactory::create([
            [
                'class' => TestHandler::class,
                'args' => [Logger::DEBUG],
            ],
        ]);

        $this->assertInstanceOf(Logger::class, $logger);
        $this->assertInstanceOf(TestHandler::class, $logger->getHandlers()[0]);
    }

    /**
     * Tests that create() uses INFO as default level when an invalid level is provided.
     */
    public function testCreateUsesDefaultLevelIfInvalidLevelProvided(): void
    {
        $logger = LoggingFactory::create([
            [
                'class' => TestHandler::class,
                'args' => ['Monolog\Level::FAKE'], // invalid level
            ],
        ]);

        $handler = $logger->getHandlers()[0];
        $this->assertInstanceOf(TestHandler::class, $handler);
    }

    /**
     * Tests that LoggingFactory::create applies a formatter if specified.
     */
    public function testCreateAppliesFormatterToHandler(): void
    {
        $logger = LoggingFactory::create([
            [
                'class' => TestHandler::class,
                'formatter' => [
                    'class' => LineFormatter::class,
                    'args' => ["[%level_name%] %message%\n"],
                ],
            ],
        ]);

        $handler = $logger->getHandlers()[0];
        $this->assertInstanceOf(TestHandler::class, $handler);

        $formatter = $handler->getFormatter();
        $this->assertInstanceOf(LineFormatter::class, $formatter);
    }

    /**
     * Tests that setLogger() and logger() correctly store and retrieve the logger.
     */
    public function testSetAndGetLogger(): void
    {
        $logger = new Logger('injected');
        LoggingFactory::setLogger($logger);

        $retrieved = LoggingFactory::logger();
        $this->assertSame($logger, $retrieved);
    }

    /**
     * Tests that logger() throws if setLogger() was not called first.
     */
    public function testLoggerThrowsIfNotInitialized(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('LoggingFactory::$logger is not initialized yet');

        LoggingFactory::logger();
    }

    /**
     * Tests that create() does not throw or fail if the handler class does not exist.
     */
    public function testCreateWithInvalidHandlerClass(): void
    {
        $logger = LoggingFactory::create([
            ['class' => 'NonExistent\\Handler']
        ]);

        $this->assertCount(0, $logger->getHandlers());
    }

    /**
     * Tests that create() skips setFormatter if handler does not support it.
     */
    public function testCreateSkipsFormatterIfNotSupported(): void
    {
        $logger = LoggingFactory::create([
            [
                'class' => NoFormatterHandler::class,
                'formatter' => [
                    'class' => LineFormatter::class,
                    'args' => ["[%level_name%] %message%\n"],
                ],
            ],
        ]);

        $this->assertInstanceOf(NoFormatterHandler::class, $logger->getHandlers()[0]);
    }

    /**
     * Tests that multiple handlers can be added via config.
     */
    public function testCreateWithMultipleHandlers(): void
    {
        $logger = LoggingFactory::create([
            ['class' => TestHandler::class],
            ['class' => TestHandler::class],
        ]);

        $this->assertCount(2, $logger->getHandlers());
    }

    /**
     * Tests that non-array values are not processed.
     */
    public function testCreateWithNonArrayValues(): void
    {
        $logger = LoggingFactory::create([
            null,
        ]);

        $this->assertCount(0, $logger->getHandlers());
    }

    /**
     * Tests with created handlers.
     */
    public function testCreateWithCreatedHandlers(): void
    {
        $logger = LoggingFactory::create([
            ['class' => new TestHandler()],
        ]);

        $this->assertCount(1, $logger->getHandlers());
        $this->assertInstanceOf(TestHandler::class, $logger->getHandlers()[0]);
    }

}
