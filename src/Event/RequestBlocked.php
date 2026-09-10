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
 * The request was refused (#218).
 *
 * Two things refuse a request, and they are worth one event rather than two because a
 * listener almost always wants both: a rule matched, or the client was already on the
 * durable block list from an earlier request. `getPlugin()` returns NULL for the second,
 * which is also the honest answer -- the block list records the key, not what put it there.
 *
 * Dispatched **after** the decision and the storage write, and before the response is sent.
 * The verdict is not negotiable at this point; see `DecisionEvent` for why that is
 * deliberate.
 */
final class RequestBlocked extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request being refused.
     * @param PluginInterface|null $plugin
     *   The rule that matched, or NULL when the durable block list did it.
     * @param int $statusCode
     *   The status the client will receive.
     * @param bool $enforced
     *   FALSE in `mode: log`, where this is a dry-run report and the request
     *   continues.
     */
    public function __construct(
        Request $request,
        private readonly ?PluginInterface $plugin,
        private readonly int $statusCode,
        private readonly bool $enforced = true
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that blocked it, if a rule did.
     *
     * @return PluginInterface|null
     *   The matched rule, or NULL for a block list hit.
     */
    public function getPlugin(): ?PluginInterface
    {
        return $this->plugin;
    }

    /**
     * Whether this was the durable block list rather than a rule.
     *
     * @return bool
     *   TRUE when the client was already blocked before this request.
     */
    public function wasAlreadyBlocked(): bool
    {
        return !$this->plugin instanceof PluginInterface;
    }

    /**
     * The status the client will receive.
     *
     * @return int
     *   The HTTP status code.
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnforced(): bool
    {
        return $this->enforced;
    }
}
