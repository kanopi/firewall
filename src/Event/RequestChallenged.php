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
     * @var array<int, string>
     */
    private array $notices = [];

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

    /**
     * Put a line of text on the challenge page this visitor is about to see (#421).
     *
     * The page is the library's in `mode: block`, so this is how a host tells a visitor
     * something only it knows. The motivating case: a visitor solves the challenge, the
     * pass cookie never comes back (an edge that strips cookies by name, a browser that
     * blocks them), and they are challenged again with nothing to say why. A host that set
     * its own short-lived marker on the solve can see the marker without the pass here,
     * and say so.
     *
     * Plain text: it is escaped when the page is written. Shown after any
     * `challenge.notice`, in the order added. Has no effect when the event is not
     * enforced (`mode: log`), because no page is served.
     *
     * @param string $notice
     *   What to tell the visitor.
     */
    public function addNotice(string $notice): void
    {
        $this->notices[] = $notice;
    }

    /**
     * The notices listeners added, in order.
     *
     * @return array<int, string>
     *   The notices.
     */
    public function getNotices(): array
    {
        return $this->notices;
    }
}
