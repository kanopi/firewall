<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Run the `firewall` command line (#289).
 *
 * Shared by bin/firewall and the deprecated bin/firewall-* wrappers, which
 * cannot include bin/firewall itself: PHP strips a shebang only from the
 * script it was started with, so an included one would be printed.
 */

// Keep stdout clean for --json. PHP's CLI sends runtime diagnostics to stdout,
// so a notice raised by a plugin or a dependency would land in the middle of a
// JSON document and break `| jq`. Startup warnings printed before this line --
// a duplicate `extension=` in php.ini -- cannot be caught from here; run with
// `php -d display_errors=stderr` if your PHP prints those.
ini_set('display_errors', 'stderr');

// This repository's own vendor/, or -- installed as a dependency, at
// vendor/kanopi/firewall/bin -- the project's.
foreach ([__DIR__ . '/../vendor/autoload.php', __DIR__ . '/../../../autoload.php'] as $autoloader) {
    if (is_file($autoloader)) {
        require_once $autoloader;
        break;
    }
}

if (!class_exists(\Kanopi\Firewall\Console\Application::class)) {
    fwrite(STDERR, "Unable to locate the Composer autoloader. Run `composer install`.\n");
    exit(2);
}

exit((new \Kanopi\Firewall\Console\Application())->run());
