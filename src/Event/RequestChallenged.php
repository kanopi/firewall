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
 * The request was asked to prove something before continuing (#218).
 *
 * Carries the provider name as well as the rule, because since per-rule providers landed
 * the two are no longer the same fact: a token is worth only what its holder actually
 * solved, and a listener measuring solve rates has to know which provider was put in front
 * of the client.
 *
 * Not dispatched when a held pass token satisfied the rule. Nothing was asked of the client
 * there, and counting it as a challenge would report a solve rate above 100%.
 */
final class RequestChallenged extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request being challenged.
     * @param PluginInterface $plugin
     *   The challenge rule that matched.
     * @param string $provider
     *   The name of the provider that will serve the challenge.
     * @param bool $enforced
     *   FALSE in `mode: log`, where the challenge is reported rather than
     *   served and the request continues.
     */
    public function __construct(
        Request $request,
        private readonly PluginInterface $plugin,
        private readonly string $provider,
        private readonly bool $enforced = true
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that asked for the challenge.
     *
     * @return PluginInterface
     *   The matched rule.
     */
    public function getPlugin(): PluginInterface
    {
        return $this->plugin;
    }

    /**
     * The provider serving it.
     *
     * @return string
     *   The configured provider name.
     */
    public function getProvider(): string
    {
        return $this->provider;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnforced(): bool
    {
        return $this->enforced;
    }
}
