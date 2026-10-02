<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

/**
 * Exception thrown when the firewall blocks a request in exception mode.
 */
class FirewallBlockedException extends FirewallException
{
    /**
     * Constructs a new FirewallBlockedException object.
     *
     * @param string $message
     *   The response body the firewall would have sent: the plain-text message, the
     *   block page, or JSON.
     * @param int $statusCode
     *   The response status.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     * @param string $contentType
     *   The body's `Content-Type` (#452). Plain text unless a block page or JSON was
     *   configured.
     */
    public function __construct(
        string $message,
        int $statusCode = 400,
        ?\Throwable $previous = null,
        private readonly string $contentType = 'text/plain; charset=utf-8'
    ) {
        parent::__construct($message, $statusCode, $previous);
    }

    /**
     * Get the HTTP status code associated with this block.
     */
    public function getStatusCode(): int
    {
        return $this->getCode();
    }

    /**
     * The `Content-Type` of the body in getMessage() (#452).
     *
     * `text/plain; charset=utf-8`, `text/html; charset=utf-8` for a block page, or
     * `application/json; charset=utf-8`. A host writing the response should send it, and
     * with `text/html`, `Kanopi\Firewall\Page\BlockPage::CONTENT_SECURITY_POLICY` too.
     */
    public function getContentType(): string
    {
        return $this->contentType;
    }
}
