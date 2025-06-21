<?php

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Bootstrap file for initializing the application environment.
 *
 * This file is intended to be used in the project root to ensure the Composer
 * autoloader is loaded before running any application logic. It allows any script
 * that includes this file to access all project dependencies and class mappings.
 *
 * Usage:
 *   require_once __DIR__ . '/load.php';
 */

require_once __DIR__ . '/vendor/autoload.php';