<?php

namespace Kanopi\Firewall\Logging;

use Monolog\Level;
use Monolog\Logger;

/**
 * Create a new Logging Stream.
 */
class LoggingFactory
{
    protected static ?Logger $logger = null;

    /**
     * Create a new Logging Element.
     *
     * @param array<int, array{
     *   class: class-string,
     *   args?: list<mixed>,
     *   formatter?: array{
     *     class: class-string,
     *     args?: list<mixed>
     *   }
     * }> $config
     *   Configuration for the Logging Element.
     * @param string $channel
     *   Channel name to use for the logger.
     */
    public static function create(array $config = [], string $channel = 'firewall'): Logger
    {
        $logger = new Logger($channel);
        $validLevels = [
            'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY',
        ];

        foreach ($config as $handlerConfig) {
            $handlerClass = $handlerConfig['class'];
            $handlerArgs = $handlerConfig['args'] ?? [];

            // Convert Monolog level string to constant (e.g., "Monolog\Level::Debug")
            foreach ($handlerArgs as &$handlerArg) {
                if (is_string($handlerArg) && str_starts_with($handlerArg, \Monolog\Level::class . '::')) {
                    $levelName = strtoupper(substr($handlerArg, strlen(\Monolog\Level::class . '::')));
                    if (!in_array($levelName, $validLevels, true)) {
                        $levelName = 'INFO';
                    }

                    $handlerArg = Level::fromName($levelName);
                }
            }

            /** @var \Monolog\Handler\HandlerInterface $handler */
            $handler = new $handlerClass(...$handlerArgs);

            // If a formatter is specified
            if (isset($handlerConfig['formatter'])) {
                $formatterClass = $handlerConfig['formatter']['class'];
                $formatterArgs = $handlerConfig['formatter']['args'] ?? [];

                $formatter = new $formatterClass(...$formatterArgs);
                if (method_exists($handler, 'setFormatter')) {
                    $handler->setFormatter($formatter);
                }
            }

            $logger->pushHandler($handler);
        }

        return $logger;
    }

    /**
     * Return a newly created logger.
     */
    public static function logger(): Logger
    {
        if (!static::$logger instanceof \Monolog\Logger) {
            throw new \Exception(
                \Kanopi\Firewall\Logging\LoggingFactory::class . '::$logger is not initialized yet. ' . \Kanopi\Firewall\Logging\LoggingFactory::class . '::setLogger() must be called.'
            );
        }

        return static::$logger;
    }

    /**
     * Set the logger.
     *
     * @param Logger $logger
     *   Logger to set for usage.
     */
    public static function setLogger(Logger $logger): void
    {
        static::$logger = $logger;
    }
}
