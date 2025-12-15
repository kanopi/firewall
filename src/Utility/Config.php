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
     * @param string $url
     *   URL to query and return the contents.
     * @param string $cacheDir
     *   Location to store the cached fie.
     * @param int $ttl
     *   How long to keep the cached file for.
     * @param float $timeout
     *   Timeout amount for remote connection.
     *
     * @return string|false
     *   Return file contents if allowed or false if ran into issues.
     */
    private static function fileGetContents(string $url, string $cacheDir = '/tmp/cache', int $ttl = 3600, float $timeout = 5.0): string|false
    {
        if (defined('KANOPI_FIREWALL_CACHE_DIR')) {
            $cacheDir = KANOPI_FIREWALL_CACHE_DIR;
        }

        if (defined('KANOPI_FIREWALL_CACHE_TTL')) {
            $ttl = intval(KANOPI_FIREWALL_CACHE_TTL);
        }

        if (defined('KANOPI_FIREWALL_CACHE_TIMEOUT')) {
            $timeout = floatval(KANOPI_FIREWALL_CACHE_TIMEOUT);
        }

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0775, true);
        }

        $cacheFile = rtrim((string) $cacheDir, '/') . '/' . md5($url) . '.cache';

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
            '(allow|block).*.metadata.storage.config.file',
            '(allow|block).*.metadata.config.*',
            '(allow|block).*.metadata.(asn_reader|reader|country_reader).db',
        ];

        if (ConfigLoader::looksLikeUrl($file)) {
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
                // Load the file and parse as Yaml.
                $config = ConfigLoader::load($file, $replacementPaths);
            } catch (\Exception) {
            }
        }

        return $config;
    }
}
