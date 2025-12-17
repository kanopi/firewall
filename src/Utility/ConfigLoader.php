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
        $absOrigin = Path::looksLikeUrl($configFilePath) ? $configFilePath : Path::realOrGiven($configFilePath);
        $baseDir = \dirname($absOrigin);
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
        $abs = Path::realOrGiven($filePath);

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

            if (!is_array($data)) {
                return [];
            }

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
        $data = TokenSubstitute::substitute($data);

        // 2) Includes: configs:
        if (!empty($data['configs']) && \is_array($data['configs'])) {
            $includes = $data['configs'];
            unset($data['configs']);

            foreach ($includes as $include) {
                if (!\is_string($include)) {
                    throw new \RuntimeException("Invalid include entry (must be string) in " . $origin);
                }

                $norm = TokenSubstitute::normalizeInclude($include, $baseDir);
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
                if (\is_string($value) && !Path::isAbsolute($value) && !Path::looksLikeUrl($value)) {
                    $candidate = $baseDir . DIRECTORY_SEPARATOR . $value;
                    if (\file_exists($candidate)) {
                        $data = self::setByPath($data, $path, Path::realOrGiven($candidate));
                    } elseif (Path::looksLikeUrl($baseDir)) {
                        if (str_contains($candidate, '{config_dir}')) {
                            $candidate = str_ireplace(['{config_dir}/','{config_dir}'], '', $candidate);
                        }

                        $data = self::setByPath($data, $path, $candidate);
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
            return \array_values(\array_filter(\array_map(trim(...), \explode('|', $t)), strlen(...)));
        }

        // Literal segment
        return [$t];
    }

    /** Split a simple CSV like "a,b,c" into ["a","b","c"] (trimmed, empty removed). */
    private static function splitAlternativesCsv(string $csv): array
    {
        return \array_values(\array_filter(\array_map(trim(...), \explode(',', $csv)), strlen(...)));
    }
}
