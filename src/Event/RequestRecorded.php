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
 * A rule wrote this client to the block list and let the request through (#203).
 *
 * The event a host most needs of the set, because it is the only decision that leaves no
 * other trace: the visitor sees an ordinary response, the access log shows an ordinary
 * request, and the consequence arrives on some *later* request as a block with no obvious
 * cause. A listener here is how an audit trail connects the two.
 *
 * `isEnforced()` is FALSE. Nothing was refused — that is the point of the action, not a
 * dry run — but a listener that acts only on enforced decisions should not act on this one
 * either, and the distinction it is really drawing is "did the visitor notice".
 */
final class RequestRecorded extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request that matched.
     * @param PluginInterface $plugin
     *   The rule that matched it.
     * @param bool $stored
     *   Whether the write to the block list succeeded. A backend that is
     *   unreachable makes this FALSE, and the rule then has no effect at all.
     */
    public function __construct(
        Request $request,
        private readonly PluginInterface $plugin,
        private readonly bool $stored
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that recorded it.
     *
     * @return PluginInterface
     *   The matched rule.
     */
    public function getPlugin(): PluginInterface
    {
        return $this->plugin;
    }

    /**
     * Whether the block list actually took the write.
     *
     * @return bool
     *   TRUE when stored.
     */
    public function wasStored(): bool
    {
        return $this->stored;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnforced(): bool
    {
        return false;
    }
}
