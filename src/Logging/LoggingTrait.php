<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Logging;

use Monolog\Logger;
use Symfony\Component\HttpFoundation\Request;

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

    /**
     * Get standard request context for logging.
     *
     * @param Request $request
     *   The request object.
     *
     * @return array
     *   Standard request context array.
     */
    protected function getRequestContext(Request $request): array
    {
        return [
            'request_id' => $request->attributes->get('x-request-id'),
            'host' => $request->getHost(),
            'client_ip' => $request->getClientIp(),
            'path' => $request->getPathInfo(),
            'method' => $request->getMethod(),
            'user_agent' => $request->headers->get('User-Agent') ?: 'unknown',
            'query_params' => $request->query->all(),
            'url' => $request->getUri(),
        ];
    }

    /**
     * Get standard request context for logging with additional context.
     *
     * @param Request $request
     *   The request object.
     * @param array $additionalContext
     *   Additional context to merge with request context.
     *
     * @return array
     *   Combined context array.
     */
    protected function getContext(Request $request, array $additionalContext = []): array
    {
        return array_merge(
            $this->getRequestContext($request),
            // @phpstan-ignore-next-line
            method_exists($this, 'getLoggingContext') ? $this->getLoggingContext() : [],
            $additionalContext
        );
    }
}
