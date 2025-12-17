<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Utility;

/**
 * Token Substitution
 *
 * A lightweight library for resolving %env(...)% placeholders following Symfony's model.
 *
 * Features:
 *  - Recursive placeholder substitution in arrays and strings
 *  - Typed returns when a value is exactly one %env(...)% token
 *  - String interpolation when tokens appear within larger strings
 *  - Chainable processors for type conversion and transformations
 *
 * Supported processors (chained left-to-right):
 *  string, int, float, bool, not, json, base64, file, resolve, require,
 *  trim, lower, upper, urlencode, urldecode, csv, shuffle, query_string,
 *  url, key, raw_key, enum, default, defined, const
 *
 * Typical usage:
 *
 *   $config = [
 *       'debug' => '%env(bool:DEBUG)%',
 *       'port' => '%env(int:PORT)%',
 *       'url' => 'https://example.com:%env(PORT)%',
 *   ];
 *
 *   $resolved = TokenSubstitute::substitute($config);
 */
final class TokenSubstitute
{
    /**
     * Substitute %env(...)% placeholders in a value.
     *
     * @param mixed $value
     *   The value to process (array, string, or scalar).
     *
     * @return mixed
     *   The value with placeholders resolved.
     *
     * @throws \RuntimeException
     *   On missing env variables, invalid casts, or malformed processor input.
     */
    public static function substitute(mixed $value): mixed
    {
        return self::resolvePlaceholders($value);
    }

    /**
     * Recursively resolves %env(...)% placeholders inside arrays and strings.
     *
     * Behavior:
     *  - If a YAML scalar is exactly one %env(...)% token, the return value is a native PHP type
     *    based on processors (e.g., bool/int/float/array/string).
     *  - If %env(...)% appears within a larger string, it is interpolated as text (string cast).
     *
     * @param mixed $value
     *   The node to process (array/scalar).
     *
     * @return mixed
     *   The node with %env(...)% placeholders resolved.
     *
     * @throws \RuntimeException
     *   On missing env variables, invalid casts, or malformed processor input.
     */
    private static function resolvePlaceholders(mixed $value): mixed
    {
        if (\is_array($value)) {
            foreach ($value as $k => $v) {
                $value[$k] = self::resolvePlaceholders($v);
            }

            return $value;
        }

        if (!\is_string($value)) {
            return $value;
        }

        // Entire scalar is a single token → typed return
        if (\preg_match('/^%env\(([^)]+)\)%$/', $value, $m)) {
            return self::resolveEnvTokenTyped($m[1]);
        }

        // Interpolate within string → cast to string
        return \preg_replace_callback(
            '/%env\(([^)]+)\)%/',
            fn(array $m): string => (string) self::resolveEnvTokenTyped($m[1]),
            $value
        );
    }

    /**
     * Resolve a single %env(...)% token and return a native PHP type when appropriate.
     *
     * Example tokens:
     *  - "MY_VAR"            → string
     *  - "int:MY_PORT"       → int
     *  - "bool:DEBUG"        → bool
     *  - "json:CFG"          → array (decoded JSON)
     *  - "file:SECRET_PATH"  → string (file contents)
     *
     * @param string $token
     *   The inside of %env(...), optionally with processors (e.g., "int:PORT").
     *
     * @return mixed
     *   A native value: bool|int|float|string|array depending on processors and data.
     *
     * @throws \RuntimeException
     *   If the env var is missing, processors are unknown, or data cannot be cast/decoded.
     */
    private static function resolveEnvTokenTyped(string $token): mixed
    {
        $parts = \explode(':', $token);
        $var = \array_pop($parts); // Last element is always the env var name

        // Handle 'defined' processor - special case that just checks existence
        if (count($parts) === 1 && strtolower($parts[0]) === 'defined') {
            return \getenv($var) !== false || isset($_SERVER[$var]);
        }

        // Handle 'const' processor - gets PHP constant instead of env var
        if (count($parts) === 1 && strtolower($parts[0]) === 'const') {
            if (!\defined($var)) {
                throw new \RuntimeException(\sprintf('Constant "%s" is not defined', $var));
            }

            return \constant($var);
        }

        // Get the initial value - check getenv() first, then $_SERVER
        $raw = \getenv($var);
        if ($raw === false && isset($_SERVER[$var])) {
            $raw = $_SERVER[$var];
        }

        // Handle 'default' processor with special logic
        $hasDefault = false;
        $defaultValue = null;
        $defaultIndex = -1;
        $counter = \count($parts);

        for ($i = 0; $i < $counter; $i++) {
            if (\strtolower(\trim($parts[$i])) === 'default') {
                if ($i + 1 >= \count($parts)) {
                    throw new \RuntimeException(\sprintf('default processor requires a value in token "%s"', $token));
                }

                $hasDefault = true;
                $defaultValue = $parts[$i + 1];
                $defaultIndex = $i;
                break;
            }
        }

        // If we have a default and the env var is not set, use the default
        if ($hasDefault && $raw === false) {
            $val = $defaultValue;
            // Remove the default processor and its value from parts
            array_splice($parts, $defaultIndex, 2);
        } elseif ($raw === false) {
            throw new \RuntimeException(\sprintf('Environment variable "%s" is not set (checked both getenv() and $_SERVER)', $var));
        } else {
            $val = $raw;
        }

        $counter = \count($parts);

        // Process each part
        for ($i = 0; $i < $counter; $i++) {
            $part = \strtolower(\trim($parts[$i]));

            switch ($part) {
                case 'string':
                    $val = (string) $val;
                    break;

                case 'int':
                    if (!\is_numeric($val)) {
                        throw new \RuntimeException(self::badCast('int', $var, $val));
                    }

                    $val = (int) $val;
                    break;

                case 'float':
                    if (!\is_numeric($val)) {
                        throw new \RuntimeException(self::badCast('float', $var, $val));
                    }

                    $val = (float) $val;
                    break;

                case 'bool':
                    $l = \strtolower((string) $val);
                    $truthy = ['1','true','yes','on'];
                    $falsey = ['0','false','no','off',''];
                    if (\in_array($l, $truthy, true)) {
                        $val = true;
                    } elseif (\in_array($l, $falsey, true)) {
                        $val = false;
                    } else {
                        throw new \RuntimeException(self::badCast('bool', $var, $val));
                    }

                    break;

                case 'not':
                    // Logical NOT - converts to bool first, then negates
                    $l = \strtolower((string) $val);
                    $truthy = ['1','true','yes','on'];
                    $val = \in_array($l, $truthy, true) || \is_numeric($val) && $val > 0 ? false : true;

                    break;

                case 'json':
                    if (\is_array($val)) {
                        // Convert array to JSON string
                        $val = \json_encode($val);
                        if ($val === false) {
                            throw new \RuntimeException(\sprintf('Failed to encode array to JSON for %s', $var));
                        }
                    } else {
                        // Parse JSON string to array
                        $d = \json_decode((string) $val, true);
                        if (\json_last_error() !== JSON_ERROR_NONE) {
                            throw new \RuntimeException(\sprintf('Invalid JSON in %s: %s', $var, \json_last_error_msg()));
                        }

                        $val = $d;
                    }

                    break;

                case 'base64':
                    if (\is_string($val) && \base64_decode($val, true) === false) {
                        throw new \RuntimeException(\sprintf('Failed to base64 decode string to %s', $var));
                    }

                    if (\is_string($val) && \base64_encode(\base64_decode($val, true)) === $val) {
                        // It's already base64, decode it
                        $val = \base64_decode($val, true);
                    } else {
                        // Encode to base64
                        $val = \base64_encode((string) $val);
                    }

                    break;

                case 'file':
                    $p = (string) $val;
                    if (!\is_file($p) || !\is_readable($p)) {
                        throw new \RuntimeException(\sprintf('file:%s not found or unreadable (from %s)', $p, $var));
                    }

                    $c = \file_get_contents($p);
                    if ($c === false) {
                        throw new \RuntimeException(\sprintf('Failed reading file for %s', $var));
                    }

                    $val = $c;
                    break;

                case 'resolve':
                    // Resolve relative paths to absolute
                    $val = \realpath((string) $val);
                    if ($val === false) {
                        throw new \RuntimeException(\sprintf('Could not resolve path for %s', $var));
                    }

                    break;

                case 'require':
                    // Include a PHP file and capture its return value
                    $p = (string) $val;
                    if (!\is_file($p) || !\is_readable($p)) {
                        throw new \RuntimeException(\sprintf('require:%s not found or unreadable (from %s)', $p, $var));
                    }

                    $val = require $p;
                    break;

                case 'trim':
                    $val = \is_string($val) ? \trim($val) : $val;
                    break;

                case 'lower':
                    $val = \strtolower((string) $val);
                    break;

                case 'upper':
                    $val = \strtoupper((string) $val);
                    break;

                case 'urlencode':
                    $val = \urlencode((string) $val);
                    break;

                case 'urldecode':
                    $val = \urldecode((string) $val);
                    break;

                case 'csv':
                    if (\is_string($val)) {
                        // Convert CSV string to array
                        $items = \array_map(trim(...), \array_filter(\explode(',', $val), strlen(...)));
                        $val = \array_values($items);
                    } elseif (\is_array($val)) {
                        // Convert array to CSV string
                        $val = \implode(',', $val);
                    }

                    break;

                case 'shuffle':
                    if (!\is_array($val)) {
                        throw new \RuntimeException(\sprintf('shuffle processor requires an array in %s', $var));
                    }

                    \shuffle($val);
                    break;

                case 'query_string':
                    $val = self::parseQueryPreserveDuplicates((string) $val);
                    break;

                case 'url':
                    $u = \parse_url((string) $val);
                    if ($u === false) {
                        throw new \RuntimeException(\sprintf('Invalid URL in %s', $var));
                    }

                    $val = $u;
                    break;

                case 'key':
                    if ($i + 1 >= \count($parts)) {
                        throw new \RuntimeException(\sprintf('key processor requires a key name in token "%s"', $token));
                    }

                    $key = $parts[++$i]; // Don't lowercase the key value

                    if (!\is_array($val)) {
                        throw new \RuntimeException(\sprintf('key processor requires an array value in %s, got %s', $var, \gettype($val)));
                    }

                    if (!\array_key_exists($key, $val)) {
                        throw new \RuntimeException(\sprintf('Key "%s" not found in %s', $key, $var));
                    }

                    $val = $val[$key];
                    break;

                case 'raw_key':
                    // Like 'key' but doesn't process the key name (for when key contains colons)
                    if ($i + 1 >= \count($parts)) {
                        throw new \RuntimeException(\sprintf('raw_key processor requires a key name in token "%s"', $token));
                    }

                    // Grab everything after raw_key up to the next processor or end
                    $keyParts = [];
                    $j = $i + 1;
                    while ($j < \count($parts) && !self::isProcessor($parts[$j])) {
                        $keyParts[] = $parts[$j];
                        $j++;
                    }

                    if ($keyParts === []) {
                        throw new \RuntimeException(\sprintf('raw_key processor requires a key name in token "%s"', $token));
                    }

                    $key = \implode(':', $keyParts);
                    $i = $j - 1; // Update index

                    if (!\is_array($val)) {
                        throw new \RuntimeException(\sprintf('raw_key processor requires an array value in %s, got %s', $var, \gettype($val)));
                    }

                    if (!\array_key_exists($key, $val)) {
                        throw new \RuntimeException(\sprintf('Key "%s" not found in %s', $key, $var));
                    }

                    $val = $val[$key];
                    break;

                case 'enum':
                    if ($i + 1 >= \count($parts)) {
                        throw new \RuntimeException(\sprintf('enum processor requires an enum class in token "%s"', $token));
                    }

                    /** @var class-string<\BackedEnum> $enumClass */
                    $enumClass = $parts[++$i]; // Keep original case for class name

                    if (!\enum_exists($enumClass)) {
                        throw new \RuntimeException(\sprintf('Enum class "%s" does not exist', $enumClass));
                    }

                    // Try to get enum by name or value
                    try {
                        // First try by name
                        $val = $enumClass::tryFrom($val) ?? $enumClass::from($val);
                    } catch (\ValueError) {
                        // Try by case name if it's a backed enum
                        $reflection = new \ReflectionEnum($enumClass);
                        foreach ($reflection->getCases() as $case) {
                            if ($case->getName() === $val) {
                                $val = $case->getValue();
                                break;
                            }
                        }

                        if (!\is_object($val) || !($val instanceof $enumClass)) {
                            throw new \RuntimeException(\sprintf('Invalid enum value "%s" for %s', $val, $enumClass));
                        }
                    }

                    break;

                case 'default':
                    // Already handled above, skip here
                    if ($i + 1 < \count($parts)) {
                        $i++; // Skip the default value
                    }

                    break;

                default:
                    throw new \RuntimeException(\sprintf('Unknown env processor "%s" in token "%s"', $part, $token));
            }
        }

        return $val;
    }

    /**
     * Helper method to check if a string is a known processor
     */
    private static function isProcessor(string $str): bool
    {
        $processors = [
            'string', 'int', 'float', 'bool', 'not', 'json', 'base64',
            'file', 'resolve', 'require', 'trim', 'lower', 'upper',
            'urlencode', 'urldecode', 'csv', 'shuffle', 'query_string',
            'url', 'key', 'raw_key', 'enum', 'default', 'defined', 'const'
        ];

        return \in_array(\strtolower(\trim($str)), $processors, true);
    }

    /**
     * Build a consistent error message for bad type casts in env processing.
     *
     * @param string $type
     *   Target type name ("int", "float", "bool").
     * @param string $var
     *   Environment variable name.
     * @param mixed  $val
     *   The original value that failed to cast.
     *
     * @return string Human-friendly error string.
     */
    private static function badCast(string $type, string $var, mixed $val): string
    {
        return \sprintf('Cannot cast %s value "%s" from %s to %s', \gettype($val), (string) $val, $var, $type);
    }

    /**
     * Parse a URL query string while preserving duplicate keys.
     * Example: "foo=1&bar=2&bar=3" becomes ["foo" => "1", "bar" => ["2","3"]]
     *
     * @param string $qs
     *   Raw query string without the leading '?'.
     *
     * @return array<string, mixed>
     *   Associative array where repeated keys are collected into arrays.
     */
    private static function parseQueryPreserveDuplicates(string $qs): array
    {
        $result = [];
        if ($qs === '') {
            return $result;
        }

        foreach (explode('&', $qs) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
            $key = urldecode($k);
            $value = urldecode($v);
            if (array_key_exists($key, $result)) {
                if (is_array($result[$key])) {
                    $result[$key][] = $value;
                } else {
                    $result[$key] = [$result[$key], $value];
                }
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * Normalize a single include entry:
     *  - Expands "{config_dir}" to the provided base directory.
     *  - Resolves a single-token %env(...)% to a string path.
     *  - If the result is not absolute and not a URL, it is joined with $baseDir.
     *
     * @param string $value
     *   The include entry from YAML.
     * @param string $baseDir
     *   The directory used for relative resolution.
     *
     * @return string
     *   Absolute (or URL/stream) path for inclusion; may contain glob patterns.
     *
     * @throws \RuntimeException
     *   If %env(...)% resolves to a non-string value.
     */
    public static function normalizeInclude(string $value, string $baseDir): string
    {
        if (\str_contains($value, '{config_dir}')) {
            $value = \str_replace('{config_dir}', $baseDir, $value);
        }

        if (\preg_match('/^%env\(([^)]+)\)%$/', $value, $m)) {
            $resolved = self::resolveEnvTokenTyped($m[1]);
            if (!\is_string($resolved)) {
                throw new \RuntimeException('%env(...)% for include must resolve to a string path');
            }

            $value = $resolved;
        }

        return Path::isAbsolute($value) ? $value : $baseDir . DIRECTORY_SEPARATOR . $value;
    }
}
