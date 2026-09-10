<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Event;

use Symfony\Component\HttpFoundation\Request;

/**
 * Something the firewall decided about a request.
 *
 * ## What this is, and what it is deliberately not
 *
 * Two different things get asked of an extension point, and they are not the same
 * request (#218):
 *
 * | | "Let me contribute a rule" | "Tell me what you decided" |
 * |---|---|---|
 * | Mechanism before this | Plugins -- good ones | **nothing** |
 * | What you had to do | Implement `PluginInterface` | Parse logs, or subclass `Firewall` |
 *
 * This is the second column. `PluginManager` and `PluginInterface` do not move, and nothing
 * a listener does can change a verdict: by the time an event is dispatched the decision is
 * made and, in the terminating modes, the response is already on its way.
 *
 * That restraint is the point. The moment a listener can influence the outcome, the plugin
 * system has been replaced by accident, without the design work that deserves (#18, #74). So
 * these carry no setters, implement no `StoppableEventInterface`, and their return value is
 * ignored.
 *
 * ## A listener that throws does not take the site down
 *
 * Dispatch is wrapped. A metrics listener whose socket is unreachable, or a notifier whose
 * queue is full, gets its exception logged at `error` and the request carries on being
 * blocked or allowed exactly as it would have been. A firewall that fails because
 * somebody's StatsD box is down has become the outage.
 *
 * ## One event per request, except in `log` mode
 *
 * `block` and `exception` terminate at the first decision, so exactly one terminal event is
 * dispatched. `mode: log` terminates nothing -- that is what makes it a dry run -- so a
 * single request can report a blocklist hit *and* a rule match *and* end up allowed. Those
 * events carry `isEnforced() === false`, the same distinction, and for the same reason, as
 * the `enforced` context key an observe-mode rule already logs (#201).
 */
abstract class DecisionEvent
{
    /**
     * @param Request $request
     *   The request the decision was made about.
     */
    public function __construct(private readonly Request $request)
    {
    }

    /**
     * The request the decision was made about.
     *
     * @return Request
     *   The request, as the firewall saw it -- so `getClientIp()` reflects
     *   whatever trusted-proxy configuration is in force.
     */
    public function getRequest(): Request
    {
        return $this->request;
    }

    /**
     * Whether the firewall acted on this decision, or only recorded it.
     *
     * FALSE in `mode: log`, where the request continues regardless. A listener
     * that notifies somebody, opens a ticket or invalidates a cache should
     * check this; one that counts things probably wants both, kept apart.
     *
     * @return bool
     *   TRUE when the decision was enforced.
     */
    public function isEnforced(): bool
    {
        return true;
    }
}
