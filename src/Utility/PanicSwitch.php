<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\FirewallMode;

/**
 * Change the firewall's mode during an incident, without a deploy.
 *
 * `global.mode` lives in YAML, so changing it is a commit, a review and a release -- during
 * exactly the window where that is most expensive (#207).
 *
 * ## Why a file rather than an environment variable
 *
 * An environment variable already works and needs nothing from this class:
 *
 * ```yaml
 * global:
 *   mode: "%env(default:block:FIREWALL_MODE)%"
 * ```
 *
 * What it cannot do is change without restarting the process that reads it. Under PHP-FPM
 * that means reloading the pool; in a container it usually means a new one. A file can be
 * created by anyone with a shell and takes effect on the next request, which is the part of
 * "without a deploy" that actually matters at 2am.
 *
 * ## It fails safe, which is the opposite of what a panic switch tempts you to build
 *
 * A file that exists but says nothing recognisable **changes nothing**. The obvious design
 * -- treat any panic file as "turn the firewall off" -- makes a leftover file from last
 * month's incident, or a stray deploy artefact, silently disable the firewall. So the file
 * has to name a mode, and an unreadable or unrecognised one is reported and ignored.
 *
 * ## The log line is the safety mechanism
 *
 * The realistic failure is not the switch being flipped. It is somebody flipping it during
 * an incident and nobody noticing three weeks later. So an active panic switch logs at
 * `warning` on every request it affects, and both `bin/firewall-check` and
 * `bin/firewall-doctor` report it.
 */
class PanicSwitch
{
    /**
     * Read the mode a panic file asks for.
     *
     * @param mixed $path
     *   The configured `global.panic_file`, as it came out of the configuration.
     *
     * @return array{active: bool, mode: FirewallMode|null, path: string|null, problem: string|null}
     *   `active` is true only when a file exists and names a mode this firewall
     *   understands. `problem` explains a file that exists and does not, which
     *   is a thing an operator needs told rather than silently ignored.
     */
    public static function read(mixed $path): array
    {
        $idle = ['active' => false, 'mode' => null, 'path' => null, 'problem' => null];

        if (!is_string($path) || trim($path) === '') {
            return $idle;
        }

        $path = trim($path);
        $idle['path'] = $path;

        // The common case by a wide margin, and the only one on the request
        // path of a firewall nobody is panicking about. One stat, no read.
        if (!is_file($path)) {
            return $idle;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            return [
                'active' => false,
                'mode' => null,
                'path' => $path,
                'problem' => 'exists but could not be read',
            ];
        }

        $requested = strtolower(trim($contents));

        if ($requested === '') {
            return [
                'active' => false,
                'mode' => null,
                'path' => $path,
                'problem' => 'is empty, so it does not say what to switch to',
            ];
        }

        $mode = FirewallMode::tryFrom($requested);

        if (!$mode instanceof FirewallMode) {
            return [
                'active' => false,
                'mode' => null,
                'path' => $path,
                'problem' => sprintf(
                    'names "%s", which is not a mode. Use one of: %s',
                    $requested,
                    implode(', ', array_map(static fn(FirewallMode $firewallMode): string => $firewallMode->value, FirewallMode::cases()))
                ),
            ];
        }

        return ['active' => true, 'mode' => $mode, 'path' => $path, 'problem' => null];
    }
}
