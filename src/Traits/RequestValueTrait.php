<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Kanopi\Firewall\Utility\RequestPath;
use Symfony\Component\HttpFoundation\Request;

/**
 * Read one named field out of a request.
 *
 * `method`, `host`, `path`, `query`, `scheme`, `port`, plus `post.x`, `header.x`,
 * `cookie.x` and `query.x` with nested keys.
 *
 * Extracted from `Url::getValue()` when rate-limit keys became composable (#200) and needed
 * the same vocabulary. Copying it would have meant two implementations of `header.*` that
 * could drift -- and one of them already carries a fix that took a release to find (#169,
 * below), which is exactly the kind of thing a copy loses.
 */
trait RequestValueTrait
{
    /**
     * Split a dotted field name into its segments.
     *
     * Its own rather than `EvaluateTrait::splitQuery()`, so this trait stands alone: a rate
     * limit has no use for the rule-evaluation machinery that trait also carries, and
     * `RateLimit` would otherwise inherit all of it to read one header.
     *
     * @param string $variable
     *   The field name.
     *
     * @return array<int|string, string>
     *   The segments, empties removed.
     */
    private function splitFieldName(string $variable): array
    {
        return array_filter(explode('.', trim($variable)), static fn(string $item): bool => $item !== '');
    }

    /**
     * How many values the client sent for one query parameter, or for all of them (#440).
     *
     * The case is facet crawling: `?f[0]=…&f[1]=…&f[2]=…&f[3]=…` in every combination, each
     * one an uncacheable faceted search. `query.f` cannot be compared -- a list resolves to
     * NULL on purpose, see below -- and the parsed query cannot be counted either, because
     * PHP keeps only the last of `f=a&f=b&f=c`. So this counts the raw query string, where
     * every way of sending a value is still there and counts the same:
     *
     *   f=a   f[]=a   f[0]=a   f[7]=a   f[x]=a   f[x][y]=a   f%5B0%5D=a   f   (no value)
     *
     * in any order, with other parameters in between. Each pair is one value under its
     * top-level name, so a nested `f[x][y]=` is one value of `f`. Names are compared as
     * the client wrote them, after percent-decoding, and case matters, as it does in the
     * query itself (#412). An absent parameter is `0`, so a numeric comparison means what it
     * says.
     *
     * @param Request $request
     *   The request.
     * @param string|null $name
     *   The parameter, or NULL for every parameter.
     *
     * @return int
     *   The number of values.
     */
    private function queryValueCount(Request $request, ?string $name): int
    {
        $raw = $request->server->get('QUERY_STRING');

        if (!is_string($raw)) {
            $raw = explode('?', $request->getRequestUri(), 2)[1] ?? '';
        }

        $count = 0;

        foreach (explode('&', $raw) as $pair) {
            if ($pair === '') {
                continue;
            }

            $key = urldecode(explode('=', $pair, 2)[0]);
            // The top-level name: everything before the first bracket.
            $top = explode('[', $key, 2)[0];

            if ($top === '') {
                continue;
            }

            if ($name === null || $top === $name) {
                ++$count;
            }
        }

        return $count;
    }

    /**
     * Resolve a field name against a request.
     *
     * @param Request $request
     *   The request to read.
     * @param string $variable
     *   The field name, dot-separated for the bags that take a key.
     *
     * @return mixed
     *   The value, or NULL when it cannot be resolved.
     */
    protected function resolveRequestValue(Request $request, string $variable): mixed
    {
        $segments = $this->splitFieldName($variable);

        if ($segments === []) {
            return null;
        }

        $isHeader = false;

        switch (strtolower((string) $segments[0])) {
            case 'method':
                return $request->getMethod();

            case 'host':
                return $request->getHost();

            case 'path':
                return RequestPath::of($request);

            case 'query_count':
                // A number, counted from the raw query string (#440).
                return $this->queryValueCount(
                    $request,
                    count($segments) === 1 ? null : implode('.', array_slice($segments, 1))
                );

            case 'query':
                if (count($segments) === 1) {
                    return $request->getQueryString();
                }

                $data = $request->query->all();
                break;

            case 'scheme':
                return $request->getScheme();

            case 'port':
                return $request->getPort();

            case 'post':
                $data = $request->request->all();
                break;

            case 'header':
                $data = $request->headers->all();
                $isHeader = true;
                // Header names are case-insensitive by spec, and Symfony
                // lowercases them on the way in. Without this, `header.User-Agent`
                // — the natural way to write it — resolves to nothing.
                $segments = array_map(
                    strtolower(...),
                    $segments
                );
                break;

            case 'cookie':
                $data = $request->cookies->all();
                break;

            default:
                return null;
        }

        if (count($segments) === 1) {
            return http_build_query($data, '', ' ');
        }

        // Traverse nested keys
        foreach (array_slice($segments, 1) as $segment) {
            if (!is_array($data) || !array_key_exists($segment, $data)) {
                return null;
            }

            $data = $data[$segment];
        }

        if ($isHeader && is_array($data)) {
            // Symfony's HeaderBag stores every header as a *list* of values,
            // because HTTP permits a field to appear more than once. Returning
            // NULL for that array is what made every `header.*` rule match
            // nothing at all, silently (#169). Fold repeats the way the spec
            // does, so `header.user-agent` is the string it looks like.
            //
            // Deliberately limited to headers. An array under `query` or
            // `post` — `?items[]=a&items[]=b` — is what the client actually
            // sent, not a storage artefact, and flattening it would let a
            // `contains` rule match across values the client never put
            // together. Those keep resolving to NULL.
            foreach ($data as $value) {
                if ($value !== null && !is_scalar($value)) {
                    return null;
                }
            }

            return implode(', ', array_map(
                static fn (mixed $value): string => (string) $value,
                $data
            ));
        }

        return is_string($data) ? $data : null;
    }
}
