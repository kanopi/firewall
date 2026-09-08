<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

/**
 * A plugin that can match without acting on it.
 *
 * `global.mode` is all-or-nothing, so an operator adding a rule to a live site could
 * either enforce it and find out, or put the *entire* firewall in log mode and stop
 * enforcing everything else. Neither is a staged rollout (#201).
 *
 * Separate from `PluginInterface` on purpose: adding a method there would make every
 * custom plugin written against the documented guide fatally incomplete on a
 * `composer update`. `AbstractPluginBase` implements this, so a plugin extending it gets
 * observe mode for free; a plugin implementing `PluginInterface` directly can opt in by
 * implementing this too.
 */
interface ObserveModeInterface
{
    /**
     * Whether this rule reports what it would have done instead of doing it.
     *
     * @return bool
     *   True when a match should be logged and then treated as no match.
     */
    public function isObserveMode(): bool;
}
