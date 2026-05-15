<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Logging;

use Monolog\Formatter\FormatterInterface;
use Monolog\Handler\HandlerInterface;
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
     * The `class` entries are intentionally typed as `mixed`: the config
     * is sourced from YAML / user input and can carry any value at
     * runtime. The runtime guards on those values are what enforce the
     * HandlerInterface / FormatterInterface contracts.
     *
     * @param array<int, mixed> $config
     *   Configuration for the Logging Element. Each entry should be an
     *   array with `class` (Monolog handler class or instance) plus
     *   optional `args` and `formatter`. Non-array entries terminate
     *   processing; non-conforming entries are silently dropped.
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
            if (!is_array($handlerConfig)) {
                break;
            }

            $handlerClass = $handlerConfig['class'] ?? '';
            $handlerArgs = $handlerConfig['args'] ?? [];

            $handler = null;
            // Reject anything that isn't a Monolog HandlerInterface before
            // calling `new`. Pre-fix the only guard was a tautological
            // `in_array(HandlerInterface::class, class_implements(HandlerInterface::class))`
            // check that only ran when $handlerClass was already an object,
            // so the string-class branch would happily instantiate arbitrary
            // classes (CWE-470) with arbitrary constructor args from config.
            if ($handlerClass instanceof HandlerInterface) {
                $handler = $handlerClass;
            } elseif (is_string($handlerClass) && $handlerClass !== '' && class_exists($handlerClass)) {
                if (!is_a($handlerClass, HandlerInterface::class, true)) {
                    // Silently reject — the logger we'd warn to has no
                    // handlers yet, so the warning would be dropped.
                    // Tests verify rejection by asserting the handler is
                    // never pushed onto the logger.
                    continue;
                }

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

                unset($handlerArg);

                $handler = new $handlerClass(...$handlerArgs);

                // If a formatter is specified
                if (isset($handlerConfig['formatter'])) {
                    $formatterClass = $handlerConfig['formatter']['class'] ?? '';
                    $formatterArgs = $handlerConfig['formatter']['args'] ?? [];

                    $formatterIsValid = is_string($formatterClass)
                        && $formatterClass !== ''
                        && class_exists($formatterClass)
                        && is_a($formatterClass, FormatterInterface::class, true);

                    if ($formatterIsValid) {
                        $formatter = new $formatterClass(...$formatterArgs);
                        if (method_exists($handler, 'setFormatter')) {
                            $handler->setFormatter($formatter);
                        }
                    }

                    // else: silently reject — see note on handler rejection above.
                }
            }

            if ($handler instanceof HandlerInterface) {
                $logger->pushHandler($handler);
            }
        }

        return $logger;
    }

    /**
     * Return a newly created logger.
     */
    public static function logger(): Logger
    {
        if (!static::$logger instanceof \Monolog\Logger) {
            static::$logger = new Logger('firewall');
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

    /**
     * Helper method to log messages when logging is available.
     *
     * @param string $level
     *   Log level.
     * @param string $message
     *   Log message.
     * @param array $context
     *   Log context.
     */
    public static function logMessage(string $level, string $message, array $context = []): void
    {
        (LoggingFactory::logger())->log($level, $message, $context);
    }
}
