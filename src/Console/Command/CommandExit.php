<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Console\Command;

/**
 * A command stopping early with an exit code (#289).
 *
 * What exit() was when the commands were scripts: thrown from wherever the
 * command decides it is done, and turned back into the exit code by
 * FirewallCommand. Never leaves the command.
 *
 * @internal
 */
final class CommandExit extends \RuntimeException
{
    public function __construct(int $code)
    {
        parent::__construct('', $code);
    }
}
