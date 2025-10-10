<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Symfony\Component\Yaml\Yaml;

/**
 * Config Loader
 *
 * A small, dependency-injection–free helper to parse YAML configuration with:
 *  - %env(...)% placeholder substitution (typed for full-scalar tokens).
 *  - Relative path resolution against the YAML file's directory (not the PHP CWD).
 *  - "configs" includes (relative/absolute paths, {config_dir} token, %env(...)%, and glob patterns).
 *  - Circular include protection and maximum include depth.
 *  - Optional per-key relative-path rewriting using dot-path patterns with '*' wildcards.
 *
 * Typical usage:
 *
 *   $config = ConfigLoader::load('/mnt/project/config.yml', [
 *       'logger.*.args.0',
 *       'block.\Kanopi\Firewall\Plugins\GeoLocation.metadata.reader.db',
 *   ]);
 *
 *   // or, when the YAML content is coming from a string, but you still want
 *   // relative paths to be based on a particular config file's location:
 *   $yaml   = file_get_contents('/mnt/project/config.yml');
 *   $config = ConfigLoader::parse($yaml, '/mnt/project/config.yml', [...]);
 */
final class ConfigLoader
{
    /** Maximum include depth to prevent accidental infinite recursion. */
    private const MAX_DEPTH = 20;

    /** @var array<string,true> Absolute file paths currently being included (circular guard). */
    private static array $includeStack = [];

    /**
     * Parse a YAML string whose "origin" is a specific config file path.
     *
     * Relative paths and "configs" includes will be resolved against dirname($configFilePath).
     * %env(...)% placeholders are expanded. When a YAML scalar is exactly a single %env(...)%
     * token, the resolved value is returned as a native PHP type (bool/int/float/array/string).
     * When %env(...)% appears inside a larger string, it is interpolated as text.
     *
     * @param string $yaml
     *   The YAML content to parse.
     * @param string $configFilePath
     *   A file path used only to determine the base directory for relative paths/includes.
     * @param array<string> $relativePathKeys
     *   Dot-path patterns (supporting '*' wildcards) that should be treated as file paths and
     *   rewritten to absolute when they are relative and exist on disk.
     *
     * @return array<string,mixed>
     *   The parsed configuration array after env substitution, includes, and relative-path resolution.
     *
     * @throws \RuntimeException
     *   If the configFilePath does not exist, includes cause circular references, or %env(...)% fails.
     */
    public static function parse(string $yaml, string $configFilePath, array $relativePathKeys = []): array
    {
        $absOrigin = self::realOrGiven($configFilePath);
        $baseDir   = \dirname($absOrigin);
        $data      = Yaml::parse($yaml) ?? [];

        return self::postProcess($data, $baseDir, $relativePathKeys, $absOrigin, 0);
    }

    /**
     * Parse a YAML file from disk.
     *
     * Relative paths and "configs" includes are resolved relative to the file's own directory.
     * %env(...)% placeholders are expanded (typed for full-scalar tokens).
     *
     * @param string $filePath
     *   Absolute or relative path to a YAML file on disk.
     * @param array<string> $relativePathKeys
     *   See parse() for details; keys to treat as path-like.
     *
     * @return array<string,mixed>
     *   The parsed configuration array after env substitution, includes, and relative-path resolution.
     *
     * @throws \RuntimeException
     *   If the file is missing/unreadable, circular includes occur, or %env(...)% fails.
     */
    public static function load(string $filePath, array $relativePathKeys = []): array
    {
        return self::loadInternal($filePath, $relativePathKeys, 0);
    }

    /**
     * Internal loader for YAML files with include depth/circular guards.
     *
     * @param string $filePath
     *   Path to YAML file.
     * @param array<string> $relativePathKeys
     *   Path-like key patterns for post-processing.
     * @param int $depth
     *   Current include depth (for guard).
     *
     * @return array<string,mixed>
     *   Fully post-processed configuration.
     *
     * @throws \RuntimeException
     *   On missing file, exceeded depth, circular include, or YAML/placeholder issues.
     */
    private static function loadInternal(string $filePath, array $relativePathKeys, int $depth): array
    {
        $abs = self::realOrGiven($filePath);

        if ($depth > self::MAX_DEPTH) {
            throw new \RuntimeException("Include depth exceeded at " . $abs);
        }

        if (isset(self::$includeStack[$abs])) {
            throw new \RuntimeException("Circular include detected at " . $abs);
        }

        self::$includeStack[$abs] = true;
        try {
            $baseDir = \dirname($abs);
            $data    = Yaml::parseFile($abs) ?? [];

            return self::postProcess($data, $baseDir, $relativePathKeys, $abs, $depth);
        } finally {
            unset(self::$includeStack[$abs]);
        }
    }

    /**
     * Common post-processing pipeline:
     *  1) %env(...)% substitution (typed for scalars that are purely a token).
     *  2) Process "configs" includes (relative to $baseDir, supporting {config_dir}, %env(...)%, and glob patterns).
     *  3) Resolve relative paths for configured key patterns against $baseDir.
     *
     * @param array<string,mixed> $data
     *   Parsed YAML as array.
     * @param string $baseDir
     *   Directory used for resolving relative paths and include entries.
     * @param array<string> $relativePathKeys
     *   Dot-path patterns for path-like values to rewrite to absolute paths.
     * @param string $origin
     *   Human-readable origin (filename) for error messages.
     * @param int $depth
     *   Current include depth (for guards).
     *
     * @return array<string,mixed>
     *   Post-processed configuration array.
     *
     * @throws \RuntimeException
     *   On invalid include entries, circular includes, depth overflow, or env resolution issues.
     */
    private static function postProcess(array $data, string $baseDir, array $relativePathKeys, string $origin, int $depth): array
    {
        // 1) %env()% substitution
        $data = self::resolvePlaceholders($data);

        // 2) Includes: configs:
        if (!empty($data['configs']) && \is_array($data['configs'])) {
            $includes = $data['configs'];
            unset($data['configs']);

            foreach ($includes as $include) {
                if (!\is_string($include)) {
                    throw new \RuntimeException("Invalid include entry (must be string) in " . $origin);
                }

                $norm = self::normalizeInclude($include, $baseDir);
                $matches = \glob($norm) ?: [$norm];
                \sort($matches, \SORT_STRING);

                foreach ($matches as $match) {
                    $sub  = self::loadInternal($match, $relativePathKeys, $depth + 1);
                    $data = self::mergeConfigs($data, $sub); // replace-lists semantics
                }
            }
        }

        // 3) Resolve relative paths for selected keys (dot-paths with * wildcards)
        if ($relativePathKeys !== []) {
            return self::resolveRelativePathsForKeys($data, $baseDir, $relativePathKeys);
        }

        return $data;
    }

    /**
     * Recursively resolves %env(...)% placeholders inside arrays and strings.
     *
     * Behavior:
     *  - If a YAML scalar is exactly one %env(...)% token, the return value is a native PHP type
     *    based on processors (e.g., bool/int/float/array/string).
     *  - If %env(...)% appears within a larger string, it is interpolated as text (string cast).
     *
     * Supported processors (chained left-to-right):
     *  string, int, float, bool, json, base64, file, trim, lower, upper, csv, query_string, url
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
        $var   = \array_pop($parts);

        $raw = \getenv($var);
        if ($raw === false) {
            throw new \RuntimeException(\sprintf('Environment variable "%s" is not set', $var));
        }

        $val = $raw;

        foreach ($parts as $part) {
            $part = \strtolower(\trim($part));
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

                case 'json':
                    $d = \json_decode((string) $val, true);
                    if (\json_last_error() !== JSON_ERROR_NONE) {
                        throw new \RuntimeException(\sprintf('Invalid JSON in %s: %s', $var, \json_last_error_msg()));
                    }

                    $val = $d; // native array
                    break;

                case 'base64':
                    $d = \base64_decode((string) $val, true);
                    if ($d === false) {
                        throw new \RuntimeException(\sprintf('Invalid base64 in %s', $var));
                    }

                    $val = $d;
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

                case 'trim':
                    $val = \is_string($val) ? \trim($val) : $val;
                    break;

                case 'lower':
                    $val = \strtolower((string) $val);
                    break;

                case 'upper':
                    $val = \strtoupper((string) $val);
                    break;

                case 'csv':
                    $items = \array_map('trim', \array_filter(\explode(',', (string) $val), 'strlen'));
                    $val = \array_values($items); // native list
                    break;

                case 'query_string':
                    \parse_str((string) $val, $arr);
                    $val = $arr; // native array
                    break;

                case 'url':
                    $u = \parse_url((string) $val);
                    if ($u === false) {
                        throw new \RuntimeException(\sprintf('Invalid URL in %s', $var));
                    }

                    $val = $u; // native array
                    break;

                default:
                    throw new \RuntimeException(\sprintf('Unknown env processor "%s" in token "%s"', $part, $token));
            }
        }

        return $val;
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
    private static function normalizeInclude(string $value, string $baseDir): string
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

        return self::isAbsolute($value) ? $value : $baseDir . DIRECTORY_SEPARATOR . $value;
    }

    /**
     * Resolve relative paths for configured dot-path patterns (supports '*' per path segment).
     *
     * For each matched scalar string value:
     *  - If it's a URL or already absolute, it is left unchanged.
     *  - If it's relative and the corresponding file exists relative to $baseDir,
     *    it is replaced with its absolute/real path.
     *
     * @param array<string,mixed> $data
     *   Configuration tree to scan/modify.
     * @param string $baseDir
     *   Base directory for relative paths.
     * @param array<string> $dotKeys
     *   Dot-path patterns to match (e.g., "logger.*.args.0").
     *
     * @return array<string,mixed>
     *   Configuration with matched relative paths rewritten.
     */
    private static function resolveRelativePathsForKeys(array $data, string $baseDir, array $dotKeys): array
    {
        foreach ($dotKeys as $dotKey) {
            foreach (self::expandMatches($data, $dotKey) as [$path, $value]) {
                if (\is_string($value) && !self::isAbsolute($value) && !self::looksLikeUrl($value)) {
                    $candidate = $baseDir . DIRECTORY_SEPARATOR . $value;
                    if (\file_exists($candidate)) {
                        $data = self::setByPath($data, $path, self::realOrGiven($candidate));
                    }
                }
            }
        }

        return $data;
    }

    /**
     * Merge two configuration arrays with "replace-lists" semantics.
     *
     * - If both sides are associative arrays, merge recursively (right overrides left).
     * - If both sides are lists (0..N integer keys in order), the right list REPLACES the left list entirely.
     * - Otherwise, the right value overwrites the left value.
     *
     * @param array<string,mixed> $base
     *   Left-hand/base configuration.
     * @param array<string,mixed> $over
     *   Right-hand/override configuration.
     *
     * @return array<string,mixed>
     *   Merged configuration.
     */
    private static function mergeConfigs(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            if (!\array_key_exists($k, $base)) {
                $base[$k] = $v;
                continue;
            }

            if (\is_array($v) && \is_array($base[$k])) {
                $baseIsList = \array_keys($base[$k]) === \range(0, \count($base[$k]) - 1);
                $overIsList = \array_keys($v) === \range(0, \count($v) - 1);
                $base[$k] = ($baseIsList && $overIsList)
                ? $v
                : self::mergeConfigs($base[$k], $v);
            } else {
                $base[$k] = $v;
            }
        }

        return $base;
    }

    /**
     * Expand a dot/wildcard path like "logger.*.args.0" to a list of ([pathArray, value]) matches.
     *
     * Each '*' matches any single key at that depth. Non-matching segments are skipped.
     *
     * Expand a dot/wildcard pattern like:
     *   "logger.*.args.0"
     *   "block|allow.\Kanopi\Firewall\Plugins\Asn.metadata.reader.db"
     *   "{block,allow}.\Kanopi\Firewall\Plugins\RateLimit.metadata.storage.config.file"
     *   "(block|allow).\Kanopi\Firewall\Plugins\GeoLocation.metadata.reader.db"
     *
     * Supported per-segment tokens:
     *   - "*"                     : match any single key
     *   - "a|b|c"                 : alternation (parentheses optional)
     *   - "{a,b,c}"               : brace alternation
     *   - literal                 : exact match
     *
     * Returns a list of ([pathSegments], value) matches.
     *
     *
     * @param array<string,mixed> $data
     *   The configuration to traverse.
     * @param string $pattern
     *   Dot-path pattern with optional '*' segments.
     *
     * @return array<int, array{0: array<int|string>, 1: mixed}>
     *   A list of tuples: [pathSegments[], value] for every match.
     */
    private static function expandMatches(array $data, string $pattern): array
    {
        $parts = \explode('.', $pattern);
        $paths = [[[], $data]]; // queue of [pathSoFar, node]
    
        foreach ($parts as $part) {
            $alts = self::tokenAlternatives($part); // e.g., ['block','allow'] or ['*'] or ['literal']
            $next = [];
    
            foreach ($paths as [$p, $node]) {
                if (!\is_array($node)) {
                    continue; // cannot descend
                }
    
                // Fast path: wildcard '*' present in alts
                if (\in_array('*', $alts, true)) {
                    foreach ($node as $k => $v) {
                        $next[] = [\array_merge($p, [$k]), $v];
                    }

                    continue;
                }
    
                // Alternation / literals
                foreach ($alts as $alt) {
                    if (\array_key_exists($alt, $node)) {
                        $next[] = [\array_merge($p, [$alt]), $node[$alt]];
                    }
                }
            }
    
            $paths = $next;
            if ($paths === []) {
                break; // no matches at this level; early exit
            }
        }
    
        return $paths;
    }

    /**
     * Set an array value by a path of keys.
     *
     * @param array<string,mixed> $data
     *   The array to modify.
     * @param array<int|string> $path
     *   List of keys (including integer indexes).
     * @param mixed $value
     *   Value to set at the given path.
     *
     * @return array<string,mixed>
     *   The modified array.
     */
    private static function setByPath(array $data, array $path, mixed $value): array
    {
        $ref =& $data;
        foreach ($path as $seg) {
            if (!\is_array($ref)) {
                $ref = [];
            }

            if (!\array_key_exists($seg, $ref)) {
                $ref[$seg] = [];
            }

            $ref =& $ref[$seg];
        }

        $ref = $value;

        return $data;
    }

    /**
     * Return a real path if available; otherwise ensure the path exists and return the original.
     *
     * Use this to gracefully handle paths where realpath() may fail (streams, zip, permissions) but the file exists.
     *
     * @param string $path
     *   The path to normalize.
     *
     * @return string
     *   Real path or the original if realpath() fails but the file exists.
     *
     * @throws \RuntimeException
     *   If the file does not exist.
     */
    private static function realOrGiven(string $path): string
    {
        $real = \realpath($path);
        if ($real !== false) {
            return $real;
        }

        if (!\file_exists($path)) {
            throw new \RuntimeException("Config not found: " . $path);
        }

        return $path; // exists but realpath failed (e.g., stream/zip/permission)
    }

    /**
     * Determine whether a path is absolute (POSIX, Windows drive, UNC) or a URL.
     *
     * @param string $p
     *   The path string to test.
     *
     * @return bool
     *   True if the path is absolute (or a URL/stream); false if it's a relative filesystem path.
     */
    private static function isAbsolute(string $p): bool
    {
        return \str_starts_with($p, '/')
        || \preg_match('~^[A-Za-z]:[\\\\/]~', $p) === 1      // Windows C:\ or C:/
        || \str_starts_with($p, '\\\\')                       // UNC \\server\share
        || \preg_match('~^[a-z][a-z0-9+.-]*://~i', $p) === 1; // scheme://
    }

    /**
     * Heuristic to decide if a string looks like a URL or stream wrapper.
     *
     * @param string $s
     *   The string to check.
     *
     * @return bool
     *   True if it looks like "scheme://..."; false otherwise.
     */
    private static function looksLikeUrl(string $s): bool
    {
        return \preg_match('~^[a-z][a-z0-9+.-]*://~i', $s) === 1;
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
     * Convert a segment token into a list of alternatives.
     * Examples:
     *   "*"                => ["*"]
     *   "block|allow"      => ["block","allow"]
     *   "(block|allow)"    => ["block","allow"]
     *   "{block,allow}"    => ["block","allow"]
     *   "literal"          => ["literal"]
     */
    private static function tokenAlternatives(string $token): array
    {
        $t = \trim($token);

        if ($t === '*') {
            return ['*'];
        }

        // Strip optional parens "(a|b|c)"
        if ($t !== '' && $t[0] === '(' && \str_ends_with($t, ')')) {
            $t = \substr($t, 1, -1);
        }

        // Brace CSV "{a,b,c}"
        if ($t !== '' && $t[0] === '{' && \str_ends_with($t, '}')) {
            $csv = \substr($t, 1, -1);
            return self::splitAlternativesCsv($csv);
        }

        // Pipe alternation "a|b|c"
        if (\str_contains($t, '|')) {
            return \array_values(\array_filter(\array_map('trim', \explode('|', $t)), 'strlen'));
        }

        // Literal segment
        return [$t];
    }

    /** Split a simple CSV like "a,b,c" into ["a","b","c"] (trimmed, empty removed). */
    private static function splitAlternativesCsv(string $csv): array
    {
        return \array_values(\array_filter(\array_map('trim', \explode(',', $csv)), 'strlen'));
    }
}
