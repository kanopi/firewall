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
     * Variable names whose log values should be replaced with [REDACTED].
     *
     * The list is matched case-insensitively and accepts a trailing `*` as
     * a wildcard suffix — e.g. `header.cookie` matches the exact name and
     * `cookie.*` matches every cookie. Operators add to or replace this
     * list with `setRedactedVariables()`; an integrator that *wants* the
     * cookie body in their firewall debug logs can pass an empty array.
     *
     * @var array<int, string>
     */
    protected static array $redactedVariables = [
        'header.cookie',
        'header.authorization',
        'header.proxy-authorization',
        'header.x-api-key',
        'header.x-auth-token',
        'header.x-csrf-token',
        'header.x-session-token',
        'cookie.*',
    ];

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

    /**
     * Replace the redacted-variable list.
     *
     * @param array<int, string> $variables
     *   Variable names (or `prefix.*` patterns) to redact in log context.
     *   Pass an empty array to disable redaction entirely.
     */
    public static function setRedactedVariables(array $variables): void
    {
        static::$redactedVariables = array_values(array_map(
            static fn ($name): string => strtolower((string) $name),
            $variables
        ));
    }

    /**
     * Return the redacted-variable list (lowercased).
     *
     * @return array<int, string>
     */
    public static function getRedactedVariables(): array
    {
        return static::$redactedVariables;
    }

    /**
     * Whether `$variable` matches any entry in the redacted list.
     *
     * Comparison is case-insensitive. A list entry ending in `.*` matches
     * any variable whose name starts with the prefix before the `.*`.
     */
    public static function shouldRedactVariable(string $variable): bool
    {
        $needle = strtolower($variable);
        foreach (static::$redactedVariables as $pattern) {
            if (str_ends_with($pattern, '.*')) {
                $prefix = substr($pattern, 0, -1); // keep trailing `.`
                if (str_starts_with($needle, $prefix)) {
                    return true;
                }
            } elseif ($needle === $pattern) {
                return true;
            }
        }

        return false;
    }
}
