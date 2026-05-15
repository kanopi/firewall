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
     * Loader function used for producing the configuration files and merging.
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
                $propertyAccessor->setValue($merged, $key, $value);
            } catch (\Exception) {
            }
        }

        return $merged;
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
     *
     * @return string|false
     *   Return file contents if allowed or false if ran into issues.
     */
    private static function fileGetContents(string $url, ?string $cacheDir = null, ?int $ttl = null, ?float $timeout = null): string|false
    {
        $cacheDir ??= defined('KANOPI_FIREWALL_CACHE_DIR') ? (string) KANOPI_FIREWALL_CACHE_DIR : '/tmp/cache';
        $ttl ??= defined('KANOPI_FIREWALL_CACHE_TTL') ? intval(KANOPI_FIREWALL_CACHE_TTL) : 3600;
        $timeout ??= defined('KANOPI_FIREWALL_CACHE_TIMEOUT') ? floatval(KANOPI_FIREWALL_CACHE_TIMEOUT) : 5.0;

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0775, true);
        }

        $cacheFile = rtrim($cacheDir, '/') . '/' . md5($url) . '.cache';

        if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < $ttl)) {
            return file_get_contents($cacheFile);
        }

        // Add timeout context
        $context = stream_context_create([
            'http' => ['timeout' => $timeout],
        ]);

        $content = @file_get_contents($url, false, $context);
        if ($content === false) {
            return false;
        }

        file_put_contents($cacheFile, $content);
        return $content;
    }

    /**
     * Load the Configuration file.
     *
     * @param string $file
     *   File to load.
     *
     * @return array
     *   Return an array of config data.
     */
    public static function loadFile(string $file): array
    {
        $config = [];

        $replacementPaths = [
            'storage.config.(storage_file|offense_file)',
            // Legacy format paths
            '(allow|block).*.metadata.storage.config.file',
            '(allow|block).*.metadata.config.*',
            '(allow|block).*.metadata.(asn_reader|reader|country_reader).db',
            // New plugins: array format paths
            'plugins.*.metadata.storage.config.file',
            'plugins.*.metadata.config.*',
            'plugins.*.metadata.(asn_reader|reader|country_reader).db',
        ];

        if (Path::looksLikeUrl($file)) {
            try {
                $contents = self::fileGetContents($file);
                if ($contents === false) {
                    return [];
                }

                $config = ConfigLoader::parse($contents, $file, $replacementPaths);
            } catch (\Exception) {
            }
        } elseif (file_exists($file) && is_file($file) && !is_dir($file) && is_readable($file)) {
            try {
                // Load the file and parse as YAML.
                $config = ConfigLoader::load($file, $replacementPaths);
            } catch (\Exception) {
            }
        }

        return $config;
    }
}
