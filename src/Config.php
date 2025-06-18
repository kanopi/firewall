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
     * Merge the config variables.
     *
     * @param string|array $default
     *   String to file, or an array fo default variables to start from.
     * @param array $configs
     *   Config variables to merge items into.
     *
     * @return array
     *   Return the merged variables.
     */
    public static function merge(string|array $default, array $configs = []): array
    {
        if (is_string($default) && file_exists($default)) {
            $default = Yaml::parse((string)@file_get_contents($default));
        }
        $default = !is_array($default) ? [] : $default;
        return array_merge([$default], $configs);
    }

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
                if (!file_exists($config)) {
                    throw new \Exception('Config file does not exist: ' . $config);
                }

                $config = (array)Yaml::parse((string)@file_get_contents($config));
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

}