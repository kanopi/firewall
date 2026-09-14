<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Utility\Schedule;

/**
 * A rule that is only awake some of the time (#205).
 *
 * Separate from `PluginInterface` for the same reason `ObserveModeInterface` is: adding a
 * method there would make every custom plugin written against the documented guide fatally
 * incomplete on a `composer update`. `AbstractPluginBase` implements this, so a plugin
 * extending it reads `metadata.active` for free; a plugin implementing `PluginInterface`
 * directly can opt in by implementing this too.
 *
 * The manager asks **before** evaluating, not after, so a sleeping rule costs a comparison
 * rather than a GeoIP lookup -- and, more importantly, a sleeping rate limit does not spend
 * a request out of somebody's budget for a window it was never going to enforce.
 */
interface ScheduledRuleInterface
{
    /**
     * Whether this rule is inside its active window right now.
     *
     * @return bool
     *   TRUE when the rule should be evaluated, which is always for a rule
     *   that configured no schedule.
     */
    public function isActiveNow(): bool;

    /**
     * The schedule this rule keeps, if it keeps one.
     *
     * @return Schedule|null
     *   NULL when the rule runs at all times, which is most of them.
     */
    public function getSchedule(): ?Schedule;
}
