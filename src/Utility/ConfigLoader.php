<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Exception\ConfigurationException;
use Symfony\Component\Yaml\Yaml;

/**
 * Config Loader
 *
 * A small, dependency-injection–free helper to parse YAML configuration with:
 *  - %env(...)% placeholder substitution (typed for full-scalar tokens).
 *  - Relative path resolution against the YAML file's directory (not the PHP CWD).
 *    Keys naming a file the library *reads* resolve only when that file exists;
 *    keys naming a file the library *writes* (see $creatablePathKeys) resolve
 *    whether or not it exists yet, since on a first run it never does (#142).
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
     * @param array<string> $creatablePathKeys
     *   Dot-path patterns naming files the library creates itself (storage state, offense
     *   sidecars, rate-limit data). These are rewritten whether or not the target exists,
     *   because on a first run it does not — the storage layer reports a genuinely bad path.
     *
     * @return array<string,mixed>
     *   The parsed configuration array after env substitution, includes, and relative-path resolution.
     *
     * @throws ConfigurationException
     *   If the configFilePath does not exist, includes cause circular references, or %env(...)% fails.
     */
    public static function parse(string $yaml, string $configFilePath, array $relativePathKeys = [], array $creatablePathKeys = []): array
    {
        $absOrigin = Path::looksLikeUrl($configFilePath) ? $configFilePath : Path::realOrGiven($configFilePath);
        $baseDir = \dirname($absOrigin);
        $data      = Yaml::parse($yaml) ?? [];

        return self::postProcess($data, $baseDir, $relativePathKeys, $absOrigin, 0, $creatablePathKeys);
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
     * @param array<string> $creatablePathKeys
     *   See parse() for details; keys naming files the library creates itself.
     *
     * @return array<string,mixed>
     *   The parsed configuration array after env substitution, includes, and relative-path resolution.
     *
     * @throws ConfigurationException
     *   If the file is missing/unreadable, circular includes occur, or %env(...)% fails.
     */
    public static function load(string $filePath, array $relativePathKeys = [], array $creatablePathKeys = []): array
    {
        return self::loadInternal($filePath, $relativePathKeys, 0, $creatablePathKeys);
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
     * @param array<string> $creatablePathKeys
     *   Key patterns naming files the library creates itself.
     *
     * @return array<string,mixed>
     *   Fully post-processed configuration.
     *
     * @throws ConfigurationException
     *   On missing file, exceeded depth, circular include, or YAML/placeholder issues.
     */
    private static function loadInternal(string $filePath, array $relativePathKeys, int $depth, array $creatablePathKeys = []): array
    {
        $abs = Path::realOrGiven($filePath);

        if ($depth > self::MAX_DEPTH) {
            throw new ConfigurationException("Include depth exceeded at " . $abs);
        }

        if (isset(self::$includeStack[$abs])) {
            throw new ConfigurationException("Circular include detected at " . $abs);
        }

        self::$includeStack[$abs] = true;
        try {
            $baseDir = \dirname($abs);
            $data = Yaml::parseFile($abs) ?? [];

            if (!is_array($data)) {
                return [];
            }

            return self::postProcess($data, $baseDir, $relativePathKeys, $abs, $depth, $creatablePathKeys);
        } finally {
            unset(self::$includeStack[$abs]);
        }
    }

    /**
     * Common post-processing pipeline:
     *  1) %env(...)% substitution (typed for scalars that are purely a token).
     *  2) Process "configs" includes (relative to $baseDir, supporting {config_dir}, %env(...)%, and glob patterns).
     *  3) Resolve relative paths for configured key patterns against $baseDir.
     *  4) Resolve relative log file paths for file-based Monolog handlers.
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
     * @param array<string> $creatablePathKeys
     *   Dot-path patterns naming files the library creates itself; rewritten even when missing.
     *
     * @return array<string,mixed>
     *   Post-processed configuration array.
     *
     * @throws ConfigurationException
     *   On invalid include entries, circular includes, depth overflow, or env resolution issues.
     */
    private static function postProcess(array $data, string $baseDir, array $relativePathKeys, string $origin, int $depth, array $creatablePathKeys = []): array
    {
        // 1) %env()% substitution
        $data = TokenSubstitute::substitute($data);

        // 2) Includes: configs:
        if (!empty($data['configs']) && \is_array($data['configs'])) {
            $includes = $data['configs'];
            unset($data['configs']);

            foreach ($includes as $include) {
                if (!\is_string($include)) {
                    throw new ConfigurationException("Invalid include entry (must be string) in " . $origin);
                }

                $norm = TokenSubstitute::normalizeInclude($include, $baseDir);
                $matches = \glob($norm) ?: [$norm];
                \sort($matches, \SORT_STRING);

                foreach ($matches as $match) {
                    $sub  = self::loadInternal($match, $relativePathKeys, $depth + 1, $creatablePathKeys);
                    $data = self::mergeConfigs($data, $sub); // replace-lists semantics
                }
            }
        }

        // 3) Resolve relative paths for selected keys (dot-paths with * wildcards)
        if ($relativePathKeys !== []) {
            $data = self::resolveRelativePathsForKeys($data, $baseDir, $relativePathKeys);
        }

        // 3b) Same, for files the library creates: resolve even when the target
        // does not exist yet, which on a first run is every one of them (#142).
        if ($creatablePathKeys !== []) {
            $data = self::resolveRelativePathsForKeys($data, $baseDir, $creatablePathKeys, true);
        }

        // 4) Log files are only a path for the handlers that take one, so they
        // cannot be expressed as a plain key pattern (#143).
        return self::resolveLoggerPaths($data, $baseDir);
    }

    /**
     * Monolog handler classes whose first constructor argument is a file path.
     *
     * `args.0` is only path-shaped for the handlers listed here. Others take
     * something else entirely in that slot — `SyslogHandler` an ident string,
     * `NativeMailerHandler` an address — so resolving the key unconditionally
     * would rewrite those values into absolute paths (#143).
     *
     * @var array<int, class-string>
     */
    private const FILE_LOG_HANDLERS = [
        \Monolog\Handler\StreamHandler::class,
        \Monolog\Handler\RotatingFileHandler::class,
    ];

    /**
     * Resolve relative paths for configured dot-path patterns (supports '*' per path segment).
     *
     * For each matched scalar string value:
     *  - If it's a URL or already absolute, it is left unchanged.
     *  - If it's relative and the corresponding file exists relative to $baseDir,
     *    it is replaced with its absolute/real path.
     *  - If $allowMissing is true, it is replaced whether or not the file exists.
     *    That is the correct behaviour for a file the library creates itself: the
     *    existence check cannot tell "this path is wrong" from "this file has not
     *    been created yet", and for those keys the second case is the normal one.
     *    Left relative, the value would resolve against the process CWD instead —
     *    so the same config behaved differently under `php -S`, php-fpm, and cron,
     *    and a first run failed outright (#142).
     *
     * @param array<string,mixed> $data
     *   Configuration tree to scan/modify.
     * @param string $baseDir
     *   Base directory for relative paths.
     * @param array<string> $dotKeys
     *   Dot-path patterns to match (e.g., "storage.config.(storage_file|offense_file)").
     * @param bool $allowMissing
     *   Resolve a matched path even when nothing exists at it yet.
     *
     * @return array<string,mixed>
     *   Configuration with matched relative paths rewritten.
     */
    private static function resolveRelativePathsForKeys(array $data, string $baseDir, array $dotKeys, bool $allowMissing = false): array
    {
        foreach ($dotKeys as $dotKey) {
            foreach (self::expandMatches($data, $dotKey) as [$path, $value]) {
                if (\is_string($value) && !Path::isAbsolute($value) && !Path::looksLikeUrl($value)) {
                    $data = self::resolveOne($data, $path, $value, $baseDir, $allowMissing);
                }
            }
        }

        return $data;
    }

    /**
     * Rewrite one matched relative value to an absolute path.
     *
     * @param array<string,mixed> $data
     *   Configuration tree to modify.
     * @param array<int, string|int> $path
     *   Dot-path segments of the value being rewritten.
     * @param string $value
     *   The relative value found at that path.
     * @param string $baseDir
     *   Base directory for relative paths.
     * @param bool $allowMissing
     *   Resolve even when nothing exists at the candidate path.
     *
     * @return array<string,mixed>
     *   Configuration with the value rewritten, or unchanged when it was left alone.
     */
    private static function resolveOne(array $data, array $path, string $value, string $baseDir, bool $allowMissing): array
    {
        $candidate = $baseDir . DIRECTORY_SEPARATOR . $value;

        if (\file_exists($candidate)) {
            return self::setByPath($data, $path, Path::realOrGiven($candidate));
        }

        // A remote base directory has nothing to stat; the joined URL is the
        // best available answer either way.
        if ($allowMissing || Path::looksLikeUrl($baseDir)) {
            return self::setByPath($data, $path, $candidate);
        }

        return $data;
    }

    /**
     * Resolve relative log file paths against the config file's directory.
     *
     * Documented in `docs/configuration/logging.md` and the quick-start guide,
     * but never implemented: `logger.*.args.0` appeared only as an example in
     * this class's docblock and was absent from the list `Config` actually
     * passes, so the value reached Monolog untouched and `StreamHandler` opened
     * it relative to the process CWD (#143).
     *
     * The key cannot simply be added to that list, because `args.0` is a path
     * for some handlers and not others — hence the class check here. The path
     * is resolved whether or not the log file exists yet, for the same reason
     * storage files are (#142); Monolog creates the file, and the directory
     * with it.
     *
     * @param array<string,mixed> $data
     *   Configuration tree to scan/modify.
     * @param string $baseDir
     *   Base directory for relative paths.
     *
     * @return array<string,mixed>
     *   Configuration with relative log paths rewritten.
     */
    private static function resolveLoggerPaths(array $data, string $baseDir): array
    {
        if (empty($data['logger']) || !\is_array($data['logger'])) {
            return $data;
        }

        foreach ($data['logger'] as $index => $handler) {
            if (!\is_array($handler)) {
                continue;
            }

            if (!\is_array($handler['args'] ?? null)) {
                continue;
            }

            $class = $handler['class'] ?? '';
            if (!\is_string($class)) {
                continue;
            }

            if (!\in_array(\ltrim($class, '\\'), self::FILE_LOG_HANDLERS, true)) {
                continue;
            }

            // `args` is spread into the constructor, so the path arrives either
            // first or under the parameter's own name.
            foreach ([0, 'stream', 'filename'] as $argKey) {
                // looksLikeUrl() also covers stream wrappers, so `php://stdout`
                // and `php://stderr` are left alone.
                $value = $handler['args'][$argKey] ?? null;
                if (!\is_string($value)) {
                    continue;
                }

                if (Path::isAbsolute($value)) {
                    continue;
                }

                if (Path::looksLikeUrl($value)) {
                    continue;
                }

                $data = self::resolveOne($data, ['logger', $index, 'args', $argKey], $value, $baseDir, true);
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
     * Special handling for plugin configurations (block/bypass sections):
     * - If a plugin has enable:false in the override, skip merging that plugin entirely
     * - The 'priority' key is preserved from the base config (not overridden)
     * - The 'config' array is appended (not replaced)
     *
     * Special handling for plugins: array (new format):
     * - Entries are APPENDED (not replaced) to support multiple plugin files
     *
     * @param array<string,mixed> $base
     *   Left-hand/base configuration.
     * @param array<string,mixed> $over
     *   Right-hand/override configuration.
     * @param array<string> $path
     *   Current path in the config tree (for detecting plugin configs).
     *
     * @return array<string,mixed>
     *   Merged configuration.
     */
    private static function mergeConfigs(array $base, array $over, array $path = []): array
    {
        foreach ($over as $k => $v) {
            $currentPath = array_merge($path, [$k]);

            if (!\array_key_exists($k, $base)) {
                $base[$k] = $v;
                continue;
            }

            if (\is_array($v) && \is_array($base[$k])) {
                // Special handling for 'plugins' array at root level: append entries
                if ($k === 'plugins' && $path === []) {
                    $baseIsList = $base[$k] === [] || \array_keys($base[$k]) === \range(0, \count($base[$k]) - 1);
                    $overIsList = $v === [] || \array_keys($v) === \range(0, \count($v) - 1);

                    if ($baseIsList && $overIsList) {
                        $base[$k] = array_merge($base[$k], $v);
                        continue;
                    }
                }

                // Detect plugin configuration: path is [block|bypass][PluginClassName]
                $isPluginConfig = count($currentPath) === 2
                    && in_array($currentPath[0], ['block', 'bypass'], true)
                    && str_contains($currentPath[1], '\\');

                if ($isPluginConfig) {
                    $baseEnabled = $base[$k]['enable'] ?? true;
                    $overEnabled = $v['enable'] ?? true;

                    // If both are disabled, remove the plugin
                    if (!$baseEnabled && !$overEnabled) {
                        unset($base[$k]);
                        continue;
                    }

                    // If base is disabled (and override is enabled, which must be true here), replace entirely
                    if (!$baseEnabled) {
                        $base[$k] = $v;
                        continue;
                    }

                    // If override is disabled, ignore it completely (don't modify base)
                    if (!$overEnabled) {
                        continue;
                    }

                    // Both enabled: merge with special rules
                    $base[$k] = self::mergePluginConfig($base[$k], $v);
                } else {
                    $baseIsList = \array_keys($base[$k]) === \range(0, \count($base[$k]) - 1);
                    $overIsList = \array_keys($v) === \range(0, \count($v) - 1);
                    $base[$k] = ($baseIsList && $overIsList)
                        ? $v
                        : self::mergeConfigs($base[$k], $v, $currentPath);
                }
            } else {
                $base[$k] = $v;
            }
        }

        return $base;
    }

    /**
     * Merge plugin configuration with special rules:
     * - Preserve 'priority' from base config
     * - Append 'config' arrays instead of replacing
     * - Other keys follow normal merge rules
     *
     * @param array<string,mixed> $base
     *   Base plugin configuration.
     * @param array<string,mixed> $over
     *   Override plugin configuration.
     *
     * @return array<string,mixed>
     *   Merged plugin configuration.
     */
    private static function mergePluginConfig(array $base, array $over): array
    {
        foreach ($over as $k => $v) {
            // Preserve priority from base
            if ($k === 'priority' && isset($base['priority'])) {
                continue;
            }

            // Append config arrays
            if ($k === 'config' && isset($base['config']) && is_array($base['config']) && is_array($v)) {
                $base['config'] = array_merge($base['config'], $v);
                continue;
            }

            // Normal merge for other keys
            $base[$k] = is_array($v) && isset($base[$k]) && is_array($base[$k]) ? self::mergeConfigs($base[$k], $v) : $v;
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
