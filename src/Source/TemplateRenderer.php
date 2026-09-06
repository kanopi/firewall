<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Utility\DotPath;

/**
 * Renders a decoded record into the shape a plugin's `config` expects.
 *
 * `IpAddress` is the one plugin taking bare values, so it usually needs no
 * template at all. Every other plugin takes rule strings — `asn:13335`,
 * `path@starts_with:/admin`, `client.name:Chrome` — and no upstream feed
 * publishes those, so a template is the normal case rather than the exception.
 *
 * `{value}` always means the record. Index into it when it is structured:
 *
 * | record shape                    | reference          |
 * |---------------------------------|--------------------|
 * | text line, or any scalar        | `{value}`          |
 * | JSON/YAML object                | `{value[ip_prefix]}` |
 * | CSV row with headers            | `{value[asn]}`     |
 * | CSV row without headers         | `{value[0]}`       |
 * | nested                          | `{value[geo][country]}` |
 * | whichever key exists            | `{value[ip_prefix|ipv6_prefix]}` |
 *
 * A literal brace is written `{{` or `}}`.
 */
final class TemplateRenderer
{
    /**
     * `{value}` with any number of `[...]` subscripts, unanchored and undelimited.
     */
    private const PLACEHOLDER_BODY = '\{value((?:\[[^\[\]]*\])*)\}';

    /**
     * The same pattern as a usable regex.
     */
    private const PLACEHOLDER = '/' . self::PLACEHOLDER_BODY . '/';

    /**
     * Stand-ins for escaped braces, held aside during interpolation.
     */
    private const LEFT_BRACE = "\x00{\x00";

    /**
     * Stand-in for an escaped closing brace.
     */
    private const RIGHT_BRACE = "\x00}\x00";

    /**
     * Render one record.
     *
     * @param mixed $record
     *   The decoded, filtered record.
     * @param string|array<array-key, mixed>|null $template
     *   Output shape. Null passes the record through untouched.
     *
     * @return mixed
     *   The rendered entry, or NULL when a placeholder could not be resolved —
     *   which the caller treats as "drop this record".
     */
    public function render(mixed $record, string|array|null $template): mixed
    {
        if ($template === null) {
            return $record;
        }

        if (is_array($template)) {
            return $this->renderStructure($record, $template);
        }

        return $this->renderString($record, $template);
    }

    /**
     * Render a map template, interpolating into its leaf strings.
     *
     * @param mixed $record
     *   The record being rendered.
     * @param array<array-key, mixed> $template
     *   A structured rule with placeholders in its leaves.
     *
     * @return array<array-key, mixed>|null
     *   The rendered structure, or NULL when any leaf failed to resolve.
     */
    private function renderStructure(mixed $record, array $template): ?array
    {
        $rendered = [];

        foreach ($template as $key => $value) {
            if (is_array($value)) {
                $nested = $this->renderStructure($record, $value);

                if ($nested === null) {
                    return null;
                }

                $rendered[$key] = $nested;
                continue;
            }

            if (is_string($value)) {
                $leaf = $this->renderString($record, $value);

                if ($leaf === null) {
                    return null;
                }

                $rendered[$key] = $leaf;
                continue;
            }

            $rendered[$key] = $value;
        }

        return $rendered;
    }

    /**
     * Interpolate placeholders in one string.
     *
     * When the template is exactly one placeholder, the resolved value is
     * returned with its own type intact — so `template: "{value[port]}"` on an
     * integer field yields an int, not the string "443". Mixed templates are
     * string concatenation and always produce a string.
     *
     * @param mixed $record
     *   The record being rendered.
     * @param string $template
     *   A template string.
     *
     * @return mixed
     *   The rendered value, or NULL when a placeholder could not be resolved.
     */
    private function renderString(mixed $record, string $template): mixed
    {
        // Take escaped braces out of play before anything looks for a
        // placeholder, so "{{value}}" is a literal rather than a match.
        $protected = str_replace(['{{', '}}'], [self::LEFT_BRACE, self::RIGHT_BRACE], $template);

        if (preg_match('/^' . self::PLACEHOLDER_BODY . '$/', $protected, $whole) === 1) {
            return $this->resolve($record, $whole[1]);
        }

        if (preg_match(self::PLACEHOLDER, $protected) !== 1) {
            return $this->restore($protected);
        }

        $failed = false;

        $result = preg_replace_callback(
            self::PLACEHOLDER,
            function (array $matches) use ($record, &$failed): string {
                $value = $this->resolve($record, $matches[1]);

                if ($value === null || is_array($value)) {
                    $failed = true;
                    return '';
                }

                return is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
            },
            $protected
        );

        if ($failed || $result === null) {
            return null;
        }

        return $this->restore($result);
    }

    /**
     * Resolve a `{value...}` placeholder against a record.
     *
     * @param mixed $record
     *   The record being rendered.
     * @param string $subscripts
     *   The raw `[a][b]` suffix, empty for a bare `{value}`.
     *
     * @return mixed
     *   The resolved value, or NULL when the path does not exist.
     */
    private function resolve(mixed $record, string $subscripts): mixed
    {
        if (trim($subscripts) === '') {
            // A bare {value} on a structured record has no sensible string
            // form; subscript into it instead.
            return is_array($record) ? null : $record;
        }

        // A literal pattern has no failure mode; the default keeps the
        // analyser happy without an unreachable branch.
        preg_match_all('/\[([^\[\]]*)\]/', $subscripts, $matches);

        $current = $record;

        foreach ($matches[1] as $segment) {
            if (!is_array($current)) {
                return null;
            }

            $found = false;

            // Resolve each segment against the alternatives it declares, so
            // "{value[ip_prefix|ipv6_prefix]}" takes whichever key is present.
            foreach (DotPath::alternatives($segment) as $alternative) {
                if ($alternative === '*') {
                    continue;
                }

                if (array_key_exists($alternative, $current)) {
                    $current = $current[$alternative];
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                return null;
            }
        }

        return $current;
    }

    /**
     * Put escaped braces back as literal braces.
     *
     * @param string $value
     *   Text containing the stand-ins.
     *
     * @return string
     *   Text with literal braces restored.
     */
    private function restore(string $value): string
    {
        return str_replace([self::LEFT_BRACE, self::RIGHT_BRACE], ['{', '}'], $value);
    }
}
