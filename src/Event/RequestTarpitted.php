<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Event;

use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A request was held still before being allowed to continue (#329).
 *
 * Non-terminal, like `RequestRecorded` and `RequestMarked`: the delay is the
 * action, and the request carries on down the ladder afterwards. A tarpit rule
 * and a block rule matching the same client compose into a slow block, which is
 * the two features doing their own jobs rather than a third one.
 *
 * `isEnforced()` is FALSE for the same reason it is on those two: nothing was
 * refused. The interesting question here is `wasHeld()`, because the answer is
 * sometimes no -- a tarpit at capacity serves the request instead of delaying
 * it, and that is the design rather than a failure. An operator watching an
 * attack needs to be able to tell the two apart, and so does a dashboard.
 */
final class RequestTarpitted extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request that was held.
     * @param PluginInterface $plugin
     *   The rule that asked for the hold.
     * @param int $seconds
     *   How long it was actually held for. Zero when it was not.
     * @param bool $held
     *   FALSE when the cap was already full, or the gauge could not answer.
     * @param int $inFlight
     *   Holds counted at the moment of the decision, including this one.
     */
    public function __construct(
        Request $request,
        private readonly PluginInterface $plugin,
        private readonly int $seconds,
        private readonly bool $held,
        private readonly int $inFlight
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that asked for the hold.
     *
     * @return PluginInterface
     *   The matched rule.
     */
    public function getPlugin(): PluginInterface
    {
        return $this->plugin;
    }

    /**
     * How long the request was held for.
     *
     * @return int
     *   Seconds, or zero when it was not held.
     */
    public function getSeconds(): int
    {
        return $this->seconds;
    }

    /**
     * Whether the request was actually delayed.
     *
     * FALSE means the cap was full or the gauge could not answer, and the
     * request was served normally. That is the tarpit protecting the site from
     * itself, not a fault.
     *
     * @return bool
     *   TRUE when the request was held.
     */
    public function wasHeld(): bool
    {
        return $this->held;
    }

    /**
     * Holds counted at the moment of the decision.
     *
     * @return int
     *   The in-flight count, or zero when the gauge could not answer.
     */
    public function getInFlight(): int
    {
        return $this->inFlight;
    }

    /**
     * {@inheritdoc}
     *
     * Always FALSE. Delaying a request is the action; nothing was refused.
     */
    public function isEnforced(): bool
    {
        return false;
    }
}
