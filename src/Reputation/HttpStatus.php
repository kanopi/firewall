<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

/**
 * The status line, out of what the stream wrapper hands back.
 *
 * One line of parsing, in one place, because both providers need it and a
 * second copy is a second thing to get wrong about a response that has been
 * redirected -- `wrapper_data` then holds the status line of every hop, and
 * the first one is the one this is looking for.
 */
final class HttpStatus
{
    /**
     * Extract the status code from stream wrapper headers.
     *
     * @param array<int, string> $headers
     *   Raw response header lines, status line first.
     *
     * @return int|null
     *   The code, or NULL when the status line could not be parsed -- which is
     *   a failure in its own right, not a reason to assume anything.
     */
    public static function fromHeaders(array $headers): ?int
    {
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return null;
    }
}
