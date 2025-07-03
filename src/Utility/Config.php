<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall;

use Kanopi\Firewall\Utility\NestedArray;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Yaml\Yaml;

/**
 * Config related items.
 */
readonly class Config
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

        /** @phpstan-ignore-next-line */
        return $merged;
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
        if (file_exists($file) && is_file($file) && !is_dir($file) && is_readable($file)) {
            try {
                // Load the file and parse as Yaml.
                $config = Yaml::parseFile($file);
            } catch (\Exception) {
            }

            // If it isn't an array make empty array.
            if (!is_array($config)) {
                $config = [];
            }
        }

        return $config;
    }
}
