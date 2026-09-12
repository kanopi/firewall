<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall;

/**
 * Enum defining the firewall operating modes.
 */
enum FirewallMode: string
{
    case Block = 'block';
    case Log = 'log';
    case Exception = 'exception';
    case Disabled = 'disabled';

    /**
     * Deny by default: nobody is served but an explicit allowlist.
     *
     * The thing you want when a site is actively being hammered and you would rather serve
     * nobody than serve the attacker. Unlike every other mode this refuses **without
     * recording** — a deliberate, temporary refusal of everybody is not evidence that any of
     * them misbehaved, and recording them would leave a block list full of customers on
     * escalating bans the moment it is lifted (#304).
     */
    case Lockdown = 'lockdown';
}
