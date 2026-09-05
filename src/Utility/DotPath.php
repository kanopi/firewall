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
 * Dot-separated path matching with wildcards and alternation.
 *
 * The syntax predates this class — `ConfigLoader` has used it since
 * `relativePathKeys` to locate values like `logger.*.args.0`. It lives here so
 * source `select:` expressions and config path resolution share one
 * implementation rather than drifting apart.
 *
 * Supported per-segment tokens:
 *   - `*`          match any single key at that depth
 *   - `a|b|c`      alternation, parentheses optional
 *   - `(a|b|c)`    the same, parenthesised
 *   - `{a,b,c}`    brace alternation
 *   - anything else is matched literally
 *
 * A segment that matches nothing prunes that branch, so a pattern which cannot
 * be satisfied yields an empty result rather than an error.
 */
final class DotPath
{
    /**
     * Expand a pattern to every ([pathSegments], value) pair it matches.
     *
     * @param array<array-key, mixed> $data
     *   The structure to traverse.
     * @param string $pattern
     *   Dot-path pattern, e.g. `prefixes.*.ip_prefix`.
     *
     * @return array<int, array{0: array<int, array-key>, 1: mixed}>
     *   One tuple per match, in traversal order.
     */
    public static function expand(array $data, string $pattern): array
    {
        $parts = \explode('.', $pattern);

        /** @var array<int, array{0: array<int, array-key>, 1: mixed}> $paths */
        $paths = [[[], $data]];

        foreach ($parts as $part) {
            $alts = self::alternatives($part);
            $next = [];

            foreach ($paths as [$path, $node]) {
                if (!\is_array($node)) {
                    // Cannot descend into a scalar.
                    continue;
                }

                if (\in_array('*', $alts, true)) {
                    foreach ($node as $key => $value) {
                        $next[] = [\array_merge($path, [$key]), $value];
                    }

                    continue;
                }

                foreach ($alts as $alt) {
                    if (\array_key_exists($alt, $node)) {
                        $next[] = [\array_merge($path, [$alt]), $node[$alt]];
                    }
                }
            }

            $paths = $next;

            if ($paths === []) {
                // Nothing matched at this depth; deeper segments cannot match.
                break;
            }
        }

        return $paths;
    }

    /**
     * Expand a pattern and return only the matched values.
     *
     * @param array<array-key, mixed> $data
     *   The structure to traverse.
     * @param string $pattern
     *   Dot-path pattern.
     *
     * @return array<int, mixed>
     *   The matched values, in traversal order.
     */
    public static function values(array $data, string $pattern): array
    {
        return \array_map(static fn (array $match): mixed => $match[1], self::expand($data, $pattern));
    }

    /**
     * Read the first value matching a pattern, or a fallback.
     *
     * Used by template interpolation, where `{value[ip_prefix|ipv6_prefix]}`
     * means "whichever of these keys this record actually has".
     *
     * @param array<array-key, mixed> $data
     *   The structure to traverse.
     * @param string $pattern
     *   Dot-path pattern.
     * @param mixed $default
     *   Returned when nothing matches.
     *
     * @return mixed
     *   The first matched value, or $default.
     */
    public static function first(array $data, string $pattern, mixed $default = null): mixed
    {
        $matches = self::expand($data, $pattern);

        return $matches === [] ? $default : $matches[0][1];
    }

    /**
     * Convert one segment token into the list of keys it may match.
     *
     * @param string $token
     *   A single dot-path segment.
     *
     * @return array<int, string>
     *   Alternatives for the segment; `['*']` for the wildcard.
     */
    public static function alternatives(string $token): array
    {
        $trimmed = \trim($token);

        if ($trimmed === '*') {
            return ['*'];
        }

        // Strip optional parentheses: "(a|b|c)".
        if ($trimmed !== '' && $trimmed[0] === '(' && \str_ends_with($trimmed, ')')) {
            $trimmed = \substr($trimmed, 1, -1);
        }

        // Brace alternation: "{a,b,c}".
        if ($trimmed !== '' && $trimmed[0] === '{' && \str_ends_with($trimmed, '}')) {
            return self::splitList(\substr($trimmed, 1, -1), ',');
        }

        // Pipe alternation: "a|b|c".
        if (\str_contains($trimmed, '|')) {
            return self::splitList($trimmed, '|');
        }

        return [$trimmed];
    }

    /**
     * Split a delimited list, trimming entries and dropping empties.
     *
     * @param string $list
     *   The raw list.
     * @param string $delimiter
     *   Delimiter to split on.
     *
     * @return array<int, string>
     *   The split entries.
     */
    private static function splitList(string $list, string $delimiter): array
    {
        return \array_values(
            \array_filter(
                \array_map(trim(...), \explode($delimiter, $list)),
                strlen(...)
            )
        );
    }
}
