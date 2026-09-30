<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

/**
 * Headers that keep a response the firewall wrote out of every cache (#417).
 *
 * Every response the firewall writes is a decision about one client: a block, a lockdown
 * refusal, a redirect, a challenge, a pass token. Served from a cache to anyone else it is
 * wrong, and for a challenge it is worse than wrong. A cached interstitial hands every
 * visitor the same single-use ALTCHA challenge: the first solver spends it, and everybody
 * after is refused and sent back to the same cached page, in a loop that lasts as long as
 * the cache entry.
 *
 * `Cache-Control: no-store` alone was not enough. Some edges, Pantheon's Fastly-based
 * Global CDN among them, cache a response that carries only `no-store`. So this sends
 * every directive a cache might be reading:
 *
 * - `private` and `max-age=0`, which shared caches reliably honour;
 * - `no-store`, `no-cache` and `must-revalidate`, for the ones that read those;
 * - `Pragma` and `Expires` for HTTP/1.0 caches;
 * - `Surrogate-Control` and `CDN-Cache-Control`, which some CDNs read in preference to
 *   `Cache-Control`.
 *
 * A host in `mode: exception` writes its own response and should send the same set:
 * `new Response($body, $status, NoStore::HEADERS + [...])`.
 */
final class NoStore
{
    /**
     * @var array<string, string>
     */
    public const HEADERS = [
        'Cache-Control' => 'private, no-store, no-cache, must-revalidate, max-age=0',
        'Pragma' => 'no-cache',
        'Expires' => '0',
        'Surrogate-Control' => 'no-store',
        'CDN-Cache-Control' => 'no-store',
    ];

    /**
     * Send the headers, replacing any of the same name already set.
     *
     * Replacing matters: a host or framework that set its own `Cache-Control` earlier in
     * the request would otherwise send both, and a cache reading the permissive one would
     * store the response anyway.
     *
     * @codeCoverageIgnore
     *   `header()` does nothing under the CLI SAPI the suite runs in. The set itself is
     *   tested through HEADERS.
     */
    public static function send(): void
    {
        foreach (self::HEADERS as $name => $value) {
            header($name . ': ' . $value, true);
        }
    }
}
