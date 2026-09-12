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
 * A rule sent this visitor somewhere instead of refusing them (#203).
 *
 * Worth counting separately from a block. A redirect is the outcome a false positive is
 * most likely to survive — they land on a page that tells them what happened and how to
 * reach somebody — so a rule whose redirects climb while its blocks stay flat is a rule
 * catching the wrong people politely.
 */
final class RequestRedirected extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request being redirected.
     * @param PluginInterface $plugin
     *   The rule that matched.
     * @param string $location
     *   Where the visitor is being sent.
     * @param int $statusCode
     *   The redirect status.
     * @param bool $enforced
     *   FALSE in `mode: log`, where the redirect is reported and the request
     *   continues.
     */
    public function __construct(
        Request $request,
        private readonly PluginInterface $plugin,
        private readonly string $location,
        private readonly int $statusCode,
        private readonly bool $enforced = true
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that redirected it.
     *
     * @return PluginInterface
     *   The matched rule.
     */
    public function getPlugin(): PluginInterface
    {
        return $this->plugin;
    }

    /**
     * Where the visitor is being sent.
     *
     * @return string
     *   The `Location` value.
     */
    public function getLocation(): string
    {
        return $this->location;
    }

    /**
     * The redirect status.
     *
     * @return int
     *   301, 302, 307 or 308.
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
