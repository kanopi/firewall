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
}
