<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Load Composer's autoloader for a `firewall` subcommand (#289).
 *
 * From this repository's own vendor/, or -- installed as a dependency, at
 * vendor/kanopi/firewall/bin/commands -- from the project's. Each command
 * still checks for the class it needs and exits with its own code if the
 * autoloader was not found, as it did when it carried this loop itself.
 *
 * @return bool
 *   Whether an autoloader was found.
 */

foreach ([__DIR__ . '/../../vendor/autoload.php', __DIR__ . '/../../../../autoload.php'] as $autoloader) {
    if (is_file($autoloader)) {
        require_once $autoloader;

        return true;
    }
}

return false;
