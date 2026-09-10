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
 * The request is going through (#218).
 *
 * Dispatched both when an allow rule matched and when nothing matched at all, because a
 * listener counting traffic needs the second case and a listener auditing bypasses needs to
 * tell them apart. `getPlugin()` is what separates them: the rule that let it through, or
 * NULL for "no rule had anything to say".
 *
 * Not dispatched for a request that ended in a block, a challenge, or a challenge
 * submission -- those have events of their own, and reporting an allow beside them would
 * double-count every request in the metrics this exists to make possible.
 */
final class RequestAllowed extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request being allowed.
     * @param PluginInterface|null $plugin
     *   The allow-bucket rule that matched, or NULL when nothing matched and
     *   the request simply reached the end of evaluation.
     */
    public function __construct(Request $request, private readonly ?PluginInterface $plugin = null)
    {
        parent::__construct($request);
    }

    /**
     * The rule that allowed it, if one did.
     *
     * @return PluginInterface|null
     *   The matched allow rule, or NULL when the request was allowed by
     *   default.
     */
    public function getPlugin(): ?PluginInterface
    {
        return $this->plugin;
    }

    /**
     * Whether a rule actively allowed this, rather than nothing objecting.
     *
     * The distinction is worth a method because it is the one an audit cares
     * about: a bypass is a rule somebody wrote, and a default allow is the
     * absence of one.
     *
     * @return bool
     *   TRUE when an allow rule matched.
     */
    public function wasBypassed(): bool
    {
        return $this->plugin instanceof PluginInterface;
    }
}
