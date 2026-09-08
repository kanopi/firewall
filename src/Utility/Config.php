<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Config related items.
 */
class Config
{
    /**
     * Load failures recorded since the last `clearLoadErrors()`.
     *
     * Loading stays lenient — `loadFile()` still returns `[]` for a file it
     * cannot read or parse — but the reason is no longer thrown away. Every
     * skipped file and every swallowed `ConfigurationException` lands here so
     * the caller can report it (or refuse to start) once a real logger
     * exists. See `Firewall::create()`, which clears this list, loads, and
     * then hands whatever accumulated to `reportConfigLoadFailures()`.
     *
     * @var array<int, array{file: string, message: string}>
     */
    private static array $loadErrors = [];

    /**
     * Degraded loads recorded since the last `clearLoadErrors()`.
     *
     * Kept apart from `$loadErrors` because these inputs *did* load. The only
     * entry today is a remote config served from a stale cache after the fetch
     * failed — content that is real, just older than the TTL allows. Reporting
     * that as a failure would let `global.require_config` refuse to start over
     * a momentary DNS blip while a known-good copy sat on disk.
     *
     * @var array<int, array{file: string, message: string}>
     */
    private static array $loadWarnings = [];

    /**
     * Loader function used for producing the configuration files and merging.
     *
     * Loading is lenient: an input that cannot be read or parsed contributes
     * nothing to the merge rather than raising. Those failures are appended
     * to the load-error list instead of vanishing — call `clearLoadErrors()`
     * beforehand and `getLoadErrors()` afterwards to find out whether the
     * merged result is actually complete.
     *
     * @param array $configs
     *   Configs to process.
     * @param array $overrides
     *   Additional overrides that should be reviewed.
     *
     * @return array
     *   Return the merged configs.
     */
    public static function load(array $configs = [], array $overrides = []): array
    {
        $cacheKey = self::configCacheKey($configs, $overrides);
        $cached = self::readConfigCache($cacheKey);

        if ($cached !== null) {
            return $cached;
        }

        ConfigLoader::takeLoadedFiles();

        $merged = [];

        /**
         * @param array<int, string|array<string, mixed>|null> $configs
         */
        foreach ($configs as $config) {
            if (is_string($config)) {
                $config = self::loadFile($config);
            } elseif (!is_array($config)) {
                $config = [];
            }

            // Merge current config into merged config
            /** @var array<string, mixed> $config */
            $merged = NestedArray::mergeDeepArray([$merged, $config]);
        }

        $propertyAccessor = PropertyAccess::createPropertyAccessorBuilder()
            ->getPropertyAccessor();

        foreach ($overrides as $key => $value) {
            try {
                self::openOverridePath($merged, (string) $key);
                $propertyAccessor->setValue($merged, $key, $value);
            } catch (\Exception) {
            }
        }

        // `%config(...)%` references are resolved last, once there is a whole
        // configuration to point into (#184). `%env()%` and `%file()%` are
        // handled per file during the parse, because a variable and a path
        // mean the same thing wherever they appear; a reference to another
        // part of the configuration does not, and resolving it here is what
        // lets one cross a `configs:` include -- which a YAML anchor cannot.
        //
        // After the overrides, so a reference written by one is resolved and a
        // reference pointing at a value an override replaced sees the new one.
        $problems = [];
        $merged = ConfigReference::resolve($merged, $problems);

        foreach ($problems as $problem) {
            // A warning rather than an error: the token is left in place, so
            // whatever reads it fails in its own terms with its own message,
            // and a bad reference in one corner of a config should not stop a
            // firewall whose rules are fine.
            self::recordLoadWarning('config references', $problem);
        }

        // Only a clean load is cached. A degraded one -- a file that could not
        // be read, a remote include served stale -- would otherwise be frozen
        // in place, and the operator would keep getting the degraded result
        // long after fixing the cause.
        if (self::$loadErrors === [] && self::$loadWarnings === []) {
            self::writeConfigCache($cacheKey, $merged, ConfigLoader::takeLoadedFiles());
        }

        return $merged;
    }

    /**
     * Identify a load by what was asked for, not by what it read.
     *
     * @param array<int, string|array<string, mixed>|null> $configs
     *   The requested configuration sources.
     * @param array<string, mixed> $overrides
     *   Runtime overrides.
     *
     * @return string
     *   A cache key.
     */
    private static function configCacheKey(array $configs, array $overrides): string
    {
        return hash('xxh128', serialize([$configs, $overrides]));
    }

    /**
     * Where the compiled configuration is kept.
     *
     * @return string|null
     *   A writable directory, or null when there is none.
     */
    private static function configCacheDir(): ?string
    {
        // The cast is taken before the concatenation, not inside it. Rector
        // strips a cast adjacent to a concat (RemoveConcatAutocastRector,
        // correctly -- concatenation casts anyway), and PHPStan then objects
        // to concatenating a mixed constant. Split, both are satisfied.
        if (defined('KANOPI_FIREWALL_CACHE_DIR')) {
            $configured = (string) KANOPI_FIREWALL_CACHE_DIR;
            $dir = $configured . '/compiled';
        } else {
            $dir = sys_get_temp_dir() . '/kanopi-firewall-config';
        }

        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return null;
        }

        return is_writable($dir) ? $dir : null;
    }

    /**
     * Return a cached merge, if one is still valid.
     *
     * Validity is checked against every file the cached load actually read --
     * including recursive `configs:` includes and `%file()%` reads, which are
     * only discoverable by having loaded once -- and against the environment,
     * because `%env()%` is resolved during the parse and baked into the result.
     *
     * Hashing the whole environment rather than tracking which variables were
     * referenced: it costs 0.0065 ms against a 5.9 ms parse, it cannot miss a
     * variable, and over-invalidating is the safe direction.
     *
     * @param string $key
     *   Cache key.
     *
     * @return array<string, mixed>|null
     *   The cached configuration, or null when there is none or it is stale.
     */
    private static function readConfigCache(string $key): ?array
    {
        $dir = self::configCacheDir();

        if ($dir === null) {
            return null;
        }

        $file = $dir . '/' . $key . '.php';

        if (!is_file($file)) {
            return null;
        }

        // The cache is PHP source, so a bad file does not merely fail to
        // parse -- it can raise inside the include, and `@` does not suppress
        // that. Left alone it would fatal on every subsequent request until
        // somebody found and deleted the file, turning a cache into an outage.
        // Catch it, throw the file away, and fall through to a real load.
        try {
            $payload = @include $file;
        } catch (\Throwable $throwable) {
            @unlink($file);

            self::recordLoadWarning($file, sprintf(
                'Compiled configuration cache could not be loaded and has been discarded: %s',
                $throwable->getMessage()
            ));

            return null;
        }

        if (!is_array($payload) || !isset($payload['config'], $payload['files'], $payload['env'])) {
            @unlink($file);

            return null;
        }

        if ($payload['env'] !== self::environmentFingerprint()) {
            return null;
        }

        foreach ($payload['files'] as $path => $fingerprint) {
            if (ConfigLoader::fileFingerprint((string) $path) !== $fingerprint) {
                return null;
            }
        }

        return $payload['config'];
    }

    /**
     * Store a merge against the files and environment it was built from.
     *
     * @param string $key
     *   Cache key.
     * @param array<string, mixed> $merged
     *   The merged configuration.
     * @param array<string, string> $files
     *   Files read, absolute path to fingerprint.
     */
    private static function writeConfigCache(string $key, array $merged, array $files): void
    {
        $dir = self::configCacheDir();

        if ($dir === null || $files === []) {
            return;
        }

        // The cache is PHP source produced by var_export(), which cannot
        // represent an object -- it emits `Foo::__set_state(...)`, and most
        // classes do not implement it. A configuration assembled in code can
        // legitimately hold one: a Monolog handler instance, a PSR-6 pool.
        //
        // serialize() would handle them and is deliberately not used. This
        // library keeps PHP serialisation out of anything it writes and reads
        // back, to eliminate the object-injection class of attack (CWE-502) --
        // FileTrait says the same about storage. A cache file is exactly the
        // kind of thing an attacker who gets a foothold would like to be
        // unserialised.
        //
        // So a configuration containing an object is simply not cached. It
        // cannot have come from YAML, which yields only scalars and arrays, so
        // this costs nothing to the file-based configurations the cache exists
        // for.
        if (self::containsObject($merged)) {
            return;
        }

        $payload = [
            'config' => $merged,
            'files' => $files,
            'env' => self::environmentFingerprint(),
        ];

        $code = '<?php return ' . var_export($payload, true) . ';';
        $temporary = $dir . '/' . $key . '.' . getmypid() . '.tmp';

        if (@file_put_contents($temporary, $code, LOCK_EX) === false) {
            return;
        }

        @chmod($temporary, 0600);

        $file = $dir . '/' . $key . '.php';

        if (!@rename($temporary, $file)) {
            @unlink($temporary);

            return;
        }

        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
    }

    /**
     * Whether a value holds an object anywhere inside it.
     *
     * @param mixed $value
     *   Value to inspect.
     *
     * @return bool
     *   True when an object is present.
     */
    private static function containsObject(mixed $value): bool
    {
        if (is_object($value)) {
            return true;
        }

        if (!is_array($value)) {
            return false;
        }

        foreach ($value as $item) {
            if (self::containsObject($item)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A fingerprint of the environment the parse would see.
     *
     * @return string
     *   The fingerprint.
     */
    private static function environmentFingerprint(): string
    {
        return hash('xxh128', serialize(getenv()) . serialize($_SERVER));
    }

    /**
     * Replace NULL nodes along an override path with empty arrays.
     *
     * `config/config.yml` — always prepended by `Firewall::create()` — ships
     * `global: ~`, `storage: ~`, `logger: ~`, `bypass: ~` and `block: ~`, all
     * of which parse to NULL. PropertyAccess cannot traverse into NULL, so it
     * throws `UnexpectedTypeException`, which `load()` swallows. The override
     * was then silently dropped: `[storage][config][file]`, `[logger][0][class]`,
     * `[global][mode]` and `[block][...][enable]` all no-opped unless the
     * caller's own YAML happened to define that section. Only `[plugins][...]`
     * worked, because `plugins: []` is already an array.
     *
     * An empty section and an absent one mean the same thing here, so opening
     * NULL to `[]` only makes the documented overrides land. Nodes holding a
     * non-NULL value are left untouched — overwriting those would discard real
     * configuration, and PropertyAccess still raises (and `load()` still
     * swallows) exactly as before.
     *
     * @param array<string, mixed> $merged
     *   Merged config to open up, by reference.
     * @param string $path
     *   PropertyAccess path the override will be written to.
     */
    private static function openOverridePath(array &$merged, string $path): void
    {
        // Only bracket notation addresses array offsets. Anything else (e.g.
        // the bare `a` in testConfigLoadWithOverridesNotValid) is not a
        // traversable array path, so leave it entirely to PropertyAccess.
        if (preg_match('/^(?:\[[^\[\]]*\])+$/', $path) !== 1) {
            return;
        }

        preg_match_all('/\[([^\[\]]*)\]/', $path, $matches);

        // The last segment is the key being written, not a node to traverse.
        $segments = $matches[1];
        array_pop($segments);

        $cursor = &$merged;
        foreach ($segments as $segment) {
            if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
                // Missing nodes are fine — PropertyAccess creates those itself.
                break;
            }

            if (is_null($cursor[$segment])) {
                $cursor[$segment] = [];
            }

            $cursor = &$cursor[$segment];
        }

        unset($cursor);
    }

    /**
     * Get the contents of a file from a remote url.
     *
     * Precedence for `$cacheDir` / `$ttl` / `$timeout`:
     *   1. The explicit argument value, if the caller passed one (not null).
     *   2. The `KANOPI_FIREWALL_CACHE_*` constant if defined.
     *   3. The built-in default.
     *
     * Explicit args used to be silently overridden by the constants, which
     * forced reflection-based tests to use `#[RunInSeparateProcess]` to get
     * a constant-free environment. Now the production caller (`loadFile()`)
     * still gets constant-driven configuration because it passes nothing,
     * while reflection tests can exercise the explicit-argument paths
     * without forking.
     *
     * @param string $url
     *   URL to query and return the contents.
     * @param string|null $cacheDir
     *   Location to store the cached file. Null falls back to
     *   `KANOPI_FIREWALL_CACHE_DIR` or `/tmp/cache`.
     * @param int|null $ttl
     *   How long to keep the cached file for. Null falls back to
     *   `KANOPI_FIREWALL_CACHE_TTL` or 3600.
     * @param float|null $timeout
     *   Timeout amount for remote connection. Null falls back to
     *   `KANOPI_FIREWALL_CACHE_TIMEOUT` or 5.0.
     * @param int|null $maxStale
     *   How far past the TTL a cached copy may still be served when the fetch
     *   fails. Null falls back to `KANOPI_FIREWALL_CACHE_MAX_STALE`, and to
     *   unbounded when that is not defined either.
     *
     * @return string|false
     *   Return file contents if allowed or false if ran into issues.
     */
    private static function fileGetContents(
        string $url,
        ?string $cacheDir = null,
        ?int $ttl = null,
        ?float $timeout = null,
        ?int $maxStale = null
    ): string|false {
        $cacheDir ??= defined('KANOPI_FIREWALL_CACHE_DIR') ? (string) KANOPI_FIREWALL_CACHE_DIR : '/tmp/cache';
        $ttl ??= defined('KANOPI_FIREWALL_CACHE_TTL') ? intval(KANOPI_FIREWALL_CACHE_TTL) : 3600;
        $timeout ??= defined('KANOPI_FIREWALL_CACHE_TIMEOUT') ? floatval(KANOPI_FIREWALL_CACHE_TIMEOUT) : 5.0;
        $maxStale ??= defined('KANOPI_FIREWALL_CACHE_MAX_STALE')
            ? intval(KANOPI_FIREWALL_CACHE_MAX_STALE)
            : null;

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0775, true);
        }

        $cacheFile = rtrim($cacheDir, '/') . '/' . md5($url) . '.cache';

        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < $ttl)) {
            return file_get_contents($cacheFile);
        }

        // Offline means offline, for every remote fetch and not only rule
        // sources (#228). Past this line a visitor pays for an HTTP round trip
        // inside Firewall::create(), before the application it is protecting
        // has done anything.
        if (self::isOffline()) {
            if (file_exists($cacheFile)) {
                $stale = @file_get_contents($cacheFile);

                if ($stale !== false) {
                    self::recordLoadWarning($url, sprintf(
                        'Running offline; served a cached copy %ds old without fetching. '
                        . 'The rules are active, but they are not necessarily current.',
                        time() - (int) @filemtime($cacheFile)
                    ));

                    return $stale;
                }
            }

            self::recordLoadError(
                $url,
                'Running offline with nothing cached, so this remote config contributed nothing. '
                . 'Warm the cache before serving requests, or unset KANOPI_FIREWALL_SOURCES_OFFLINE.'
            );

            return false;
        }

        // Only one process should pay for the refresh. Without this, a TTL
        // lapsing under load sends every concurrent worker at the same URL at
        // once -- and each of them can wait the full timeout (#228).
        $singleFlight = self::claimRefresh($cacheFile);

        if ($singleFlight === false && file_exists($cacheFile)) {
            $stale = @file_get_contents($cacheFile);

            if ($stale !== false) {
                return $stale;
            }
        }

        // Add timeout context
        $context = stream_context_create([
            'http' => ['timeout' => $timeout],
        ]);

        $content = @file_get_contents($url, false, $context);

        self::releaseRefresh($singleFlight, $cacheFile);

        if ($content === false) {
            // The fetch failed, but a copy that once worked may be sitting
            // right there. Discarding it drops the whole ruleset over a CDN
            // 503 or a DNS blip — and for a `response: allow` include at
            // negative weight, dropping it starts blocking the monitoring and
            // deploy traffic it existed to let through. Serve it, and say so.
            return self::serveStaleCache($url, $cacheFile, $maxStale);
        }

        self::writeCache($cacheFile, $content);
        return $content;
    }

    /**
     * Whether remote fetching is switched off.
     *
     * Reads the constant rule sources already use. The name says "sources",
     * but an operator who set it meant "do not make HTTP requests while
     * serving a request", and a remote `configs:` include is one of those.
     */
    private static function isOffline(): bool
    {
        return defined('KANOPI_FIREWALL_SOURCES_OFFLINE')
            && (bool) constant('KANOPI_FIREWALL_SOURCES_OFFLINE');
    }

    /**
     * Try to become the one process that refreshes this URL.
     *
     * Never blocks. A caller that does not get the claim serves its cached
     * copy if it has one, and otherwise fetches anyway -- a cold cache with no
     * copy to fall back on needs the content more than it needs the politeness.
     *
     * @param string $cacheFile
     *   The cache file being refreshed.
     *
     * @return resource|false
     *   The held handle, or false when another process holds the claim.
     */
    private static function claimRefresh(string $cacheFile)
    {
        $handle = @fopen($cacheFile . '.refresh', 'c');

        if ($handle === false) {
            return false;
        }

        if (!@flock($handle, LOCK_EX | LOCK_NB)) {
            @fclose($handle);
            return false;
        }

        return $handle;
    }

    /**
     * Release a refresh claim.
     *
     * @param resource|false $handle
     *   Whatever claimRefresh() returned.
     * @param string $cacheFile
     *   The cache file being refreshed.
     */
    private static function releaseRefresh($handle, string $cacheFile): void
    {
        if ($handle === false) {
            return;
        }

        @flock($handle, LOCK_UN);
        @fclose($handle);
        @unlink($cacheFile . '.refresh');
    }

    /**
     * Publish the cache file atomically.
     *
     * Written in place before, so a concurrent reader could pick up a partial
     * file and hand it to the YAML parser as though it were the whole config
     * (#228, and the same fix as #225 for storage).
     *
     * @param string $cacheFile
     *   Destination.
     * @param string $content
     *   What to write.
     */
    private static function writeCache(string $cacheFile, string $content): void
    {
        $temporary = $cacheFile . '.' . getmypid() . '.tmp';

        if (@file_put_contents($temporary, $content, LOCK_EX) === false) {
            return;
        }

        if (!@rename($temporary, $cacheFile)) {
            @unlink($temporary);
        }
    }

    /**
     * Fall back to a cached copy after a failed fetch.
     *
     * Deliberately does not touch the cache file's mtime. Restamping it would
     * reset the TTL and hide how old the content is, so a permanently dead
     * upstream would look healthy forever.
     *
     * @param string $url
     *   The URL that could not be fetched.
     * @param string $cacheFile
     *   Where its last good copy would be.
     * @param int|null $maxStale
     *   Seconds past the TTL a copy may still be served, or NULL for unbounded.
     *
     * @return string|false
     *   The stale contents, or FALSE when there is nothing usable to fall back to.
     */
    private static function serveStaleCache(string $url, string $cacheFile, ?int $maxStale): string|false
    {
        if (!file_exists($cacheFile)) {
            return false;
        }

        $age = time() - (int) @filemtime($cacheFile);

        if ($maxStale !== null && $age > $maxStale) {
            self::recordLoadError($url, sprintf(
                'Remote config could not be fetched and the cached copy is %ds old, beyond the %ds '
                . 'allowed by KANOPI_FIREWALL_CACHE_MAX_STALE.',
                $age,
                $maxStale
            ));

            return false;
        }

        $stale = @file_get_contents($cacheFile);

        if ($stale === false) {
            self::recordLoadError(
                $url,
                'Remote config could not be fetched and its cached copy could not be read.'
            );

            return false;
        }

        self::recordLoadWarning($url, sprintf(
            'Remote config could not be fetched; served a cached copy %ds old. '
            . 'The rules are active, but they are not necessarily current.',
            $age
        ));

        return $stale;
    }

    /**
     * Failures recorded since the last `clearLoadErrors()` call.
     *
     * @return array<int, array{file: string, message: string}>
     *   One entry per config input that could not be loaded, in the order
     *   they were attempted. Empty when everything loaded.
     */
    public static function getLoadErrors(): array
    {
        return self::$loadErrors;
    }

    /**
     * Degraded loads recorded since the last `clearLoadErrors()` call.
     *
     * Separate from the error list because these are not failures. Serving a
     * stale remote config is a *successful* load of older content — reporting
     * it as an error would make `global.require_config` refuse to start over a
     * transient CDN blip, while perfectly good config sat in the cache.
     *
     * @return array<int, array{file: string, message: string}>
     *   One entry per input that loaded, but not from the source it names.
     */
    public static function getLoadWarnings(): array
    {
        return self::$loadWarnings;
    }

    /**
     * Discard recorded load failures.
     *
     * Call this before a `load()` you intend to inspect, so failures from an
     * earlier load (or from another firewall instance in the same process)
     * are not attributed to it. Clears the warning list too, so a caller that
     * already resets errors does not silently inherit stale warnings.
     */
    public static function clearLoadErrors(): void
    {
        self::$loadErrors = [];
        self::$loadWarnings = [];
    }

    /**
     * Record a config input that could not be loaded.
     *
     * Recording rather than logging on the spot is deliberate. The main
     * caller — `Firewall::create()` — loads config *before*
     * `LoggingFactory::setLogger()` runs, so a log written here would go to a
     * handler-less bootstrap logger on a cold start and be lost, yet would
     * duplicate the caller's report in a long-running process where a logger
     * from a previous `create()` is still installed. Each caller reports the
     * list it collected, exactly once, when it has a logger.
     *
     * @param string $file
     *   The config input that failed.
     * @param string $message
     *   Why it failed, in operator-readable terms.
     */
    private static function recordLoadError(string $file, string $message): void
    {
        self::$loadErrors[] = ['file' => $file, 'message' => $message];
    }

    /**
     * Record a config input that loaded, but in a degraded way.
     *
     * Recorded rather than logged for the same reason as `recordLoadError()`:
     * config is read before a logger exists.
     *
     * @param string $file
     *   The config input.
     * @param string $message
     *   What was degraded, in operator-readable terms.
     */
    private static function recordLoadWarning(string $file, string $message): void
    {
        self::$loadWarnings[] = ['file' => $file, 'message' => $message];
    }

    /**
     * Move anything ConfigLoader recorded into this class's error list.
     *
     * ConfigLoader cannot reach `recordLoadError()`, and a document that parses
     * to a scalar is not an exception it could throw without aborting an entire
     * include chain. So it records, and this drains.
     *
     * @param string $file
     *   The input being loaded, used when ConfigLoader named a nested include.
     */
    private static function drainLoaderErrors(string $file): void
    {
        foreach (ConfigLoader::takeLoadErrors() as $error) {
            self::recordLoadError($error['file'] ?: $file, $error['message']);
        }
    }

    /**
     * Explain why a local path was not loaded.
     *
     * @param string $file
     *   Path that failed the readability gate in `loadFile()`.
     *
     * @return string
     *   Operator-readable reason.
     */
    private static function describeUnreadablePath(string $file): string
    {
        if (!file_exists($file)) {
            return 'File does not exist.';
        }

        if (is_dir($file)) {
            return 'Path is a directory, not a config file.';
        }

        if (!is_file($file)) {
            return 'Path is not a regular file.';
        }

        return 'File is not readable — check filesystem permissions.';
    }

    /**
     * Load the Configuration file.
     *
     * Never throws. A missing, unreadable, or malformed file yields `[]`, but
     * the reason is recorded on the class (see `getLoadErrors()`) instead of
     * being discarded. Callers report or escalate it: `Firewall::create()`
     * logs every failure at `error` level and turns a non-empty list into a
     * `ConfigurationException` when `global.require_config` is enabled.
     *
     * @param string $file
     *   File to load.
     *
     * @return array
     *   Return an array of config data, or an empty array when the file could
     *   not be read or parsed.
     */
    public static function loadFile(string $file): array
    {
        $config = [];

        // Files the firewall reads. These resolve only when the target exists:
        // a wrong path here stays relative and is reported by whatever tried to
        // read it. `metadata.config.*` in particular is a wildcard over plugin
        // config *files*, so it must not rewrite a value that is not one.
        $replacementPaths = [
            // Legacy format paths
            '(allow|block).*.metadata.config.*',
            '(allow|block).*.metadata.(asn_reader|reader|country_reader).db',
            // New plugins: array format paths
            'plugins.*.metadata.config.*',
            'plugins.*.metadata.(asn_reader|reader|country_reader).db',
            // Rule sources. Without these a preset that ships its list
            // alongside itself cannot name it: a relative `upstream` stayed
            // relative and was read against the process working directory,
            // which for a web request is wherever the front controller
            // happens to be. Both the string and map forms of `upstream`
            // are covered; a URL is left alone by the resolver.
            'plugins.*.metadata.sources.*.upstream',
            'plugins.*.metadata.sources.*.upstream.url',
            '(allow|block).*.metadata.sources.*.upstream',
            '(allow|block).*.metadata.sources.*.upstream.url',
        ];

        // Files the firewall *writes*: block-list state, the offense sidecar,
        // and rate-limit data. None of them exist on a first run, which is
        // exactly when resolution is needed, so these resolve unconditionally
        // (#142). A genuinely bad path is reported by the storage layer, which
        // now sees the same absolute path the config author meant.
        $creatablePaths = [
            'storage.config.(storage_file|offense_file)',
            '(allow|block).*.metadata.storage.config.file',
            'plugins.*.metadata.storage.config.file',
        ];

        if (Path::looksLikeUrl($file)) {
            try {
                $contents = self::fileGetContents($file);
                if ($contents === false) {
                    // fileGetContents() records the specific reason when a
                    // cached copy existed but could not be used. Only describe
                    // the failure generically when it said nothing.
                    if (self::$loadErrors === []) {
                        self::recordLoadError(
                            $file,
                            'Remote config could not be fetched (network error, non-200 response, or timeout).'
                        );
                    }

                    return [];
                }

                $config = ConfigLoader::parse($contents, $file, $replacementPaths, $creatablePaths);
            } catch (\Exception $exception) {
                self::recordLoadError($file, $exception->getMessage());
            } finally {
                self::drainLoaderErrors($file);
            }
        } elseif (file_exists($file) && is_file($file) && !is_dir($file) && is_readable($file)) {
            try {
                // Load the file and parse as YAML.
                $config = ConfigLoader::load($file, $replacementPaths, $creatablePaths);
            } catch (\Exception $exception) {
                // Everything ConfigLoader is careful to raise — malformed
                // YAML, circular `configs:` includes, depth overflow, an
                // unresolvable %env(...)% token, a disabled file:/require:
                // processor — arrives here. Discarding it is what turned a
                // broken ruleset into a firewall that allows everything (#78).
                self::recordLoadError($file, $exception->getMessage());
            } finally {
                self::drainLoaderErrors($file);
            }
        } else {
            // No `else` used to exist at all: a mistyped path fell through
            // both branches and returned [] as if the file had been empty.
            self::recordLoadError($file, self::describeUnreadablePath($file));
        }

        return $config;
    }
}
