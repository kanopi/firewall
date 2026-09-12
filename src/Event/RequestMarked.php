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
 * A rule found this request suspicious and did nothing about it (#203).
 *
 * `response: mark` turns the firewall into a signal source rather than a gate: a comment
 * form can show a CAPTCHA only to requests that were marked, instead of to everybody, and
 * the decision stays with the application that knows what the request was trying to do.
 *
 * **This event is the reliable channel.** The attribute the firewall sets is only visible to
 * code holding the same `Request` instance — which a Symfony or Laravel integration does,
 * and a `settings.php` bootstrap that later builds its own request object does not. A
 * listener is told regardless.
 */
final class RequestMarked extends DecisionEvent
{
    /**
     * @param Request $request
     *   The request that was marked.
     * @param PluginInterface $plugin
     *   The rule that marked it.
     * @param string $mark
     *   The name of the signal — the rule's name unless `metadata.mark_as`
     *   says otherwise.
     * @param string $attribute
     *   The request attribute the firewall set.
     */
    public function __construct(
        Request $request,
        private readonly PluginInterface $plugin,
        private readonly string $mark,
        private readonly string $attribute
    ) {
        parent::__construct($request);
    }

    /**
     * The rule that marked it.
     *
     * @return PluginInterface
     *   The matched rule.
     */
    public function getPlugin(): PluginInterface
    {
        return $this->plugin;
    }

    /**
     * The signal's name.
     *
     * @return string
     *   What was raised, rather than where it was written.
     */
    public function getMark(): string
    {
        return $this->mark;
    }

    /**
     * The request attribute the firewall set.
     *
     * @return string
     *   The full attribute key.
     */
    public function getAttribute(): string
    {
        return $this->attribute;
    }

    /**
     * {@inheritdoc}
     *
     * Always FALSE. Marking is the action; nothing was enforced, and nothing was meant to
     * be.
     */
    public function isEnforced(): bool
    {
        return false;
    }
}
