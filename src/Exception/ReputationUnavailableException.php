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
 * A reputation provider could not answer (#204).
 *
 * Thrown, rather than returned as a null verdict, so that failing open is the
 * behaviour a provider gets for free and failing closed is something somebody
 * would have to write on purpose. A provider that times out, is refused, has
 * spent its quota or hands back something that is not a verdict throws this;
 * the plugin catches every one of them in one place, logs it, caches it
 * briefly and lets the request continue.
 *
 * The message is written for an operator reading a log line at 2am -- "the
 * daily quota is exhausted", not "HTTP 429" -- because that is the only place
 * it is ever shown.
 */
class ReputationUnavailableException extends \RuntimeException
{
    /**
     * @param string $message
     *   What went wrong, in terms somebody can act on.
     * @param int|null $httpStatus
     *   The status that caused it, when there was one. Recorded for the log
     *   line; nothing branches on it.
     */
    public function __construct(string $message, public readonly ?int $httpStatus = null)
    {
        parent::__construct($message);
    }
}
