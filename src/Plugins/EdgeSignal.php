<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Traits\EdgeTrustTrait;
use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Utility\EdgeSignalMap;
use Symfony\Component\HttpFoundation\Request;

/**
 * Match on what the CDN worked out that the origin cannot (#206).
 *
 * ```yaml
 * - plugin: "Kanopi\\Firewall\\Plugins\\EdgeSignal"
 *   response: block
 *   metadata:
 *     name: cloudflare-bots
 *     provider: cloudflare
 *   config:
 *     - "bot_score <= 5"
 * ```
 *
 * Two kinds of signal, and they are worth different things.
 *
 * **A TLS fingerprint** -- `ja3`, `ja4` -- identifies the *client stack*: the
 * cipher suites, extensions and curves it offered, in the order it offered
 * them. A script wearing a browser's User-Agent still negotiates TLS like a
 * script, so this catches the thing a User-Agent rule cannot. It is the gap
 * reverse-DNS verification (#199) closes for crawlers, closed differently for
 * everything else.
 *
 * **A bot score** is the edge's own verdict, computed from signals -- request
 * timing, TLS, behaviour across the whole network -- that never reach the
 * origin at all.
 *
 * Neither is computed here. The edge already decided, and this reads the
 * decision. Scope, deliberately: fingerprinting belongs to the edge.
 *
 * ## Cloudflare's bot score runs the other way round
 *
 * `cf-bot-score` is **1 for a certain bot and 99 for a certain human** -- the
 * opposite direction to every reputation score in this library, where high is
 * bad. So the rule that blocks bots is `bot_score <= 5`, and `bot_score > 30`
 * on a `response: block` rule blocks *humans*, which is an outage that looks
 * like a working configuration. `firewall-check --lint` warns about that shape.
 *
 * ## It does nothing without trusted proxies
 *
 * These headers are claims, and a request straight to the origin can set
 * `cf-bot-score: 99`. Every one of them is ignored unless the request arrived
 * through a trusted proxy, and a request that did not say so is logged at
 * `warning` -- because a rule matching nothing looks exactly like a quiet day.
 */
class EdgeSignal extends AbstractPluginBase
{
    use EdgeTrustTrait;
    use EvaluateTrait;

    /**
     * Header mapping for the configured CDN.
     */
    protected EdgeSignalMap $edgeSignalMap;

    /**
     * Signals the edge sent for the request being evaluated.
     *
     * @var array<string, string>
     */
    protected array $signals = [];

    /**
     * Constructs a new EdgeSignal rule.
     *
     * @param array<int|string, mixed> $metadata
     *   Metadata for the plugin.
     * @param array<int|string, mixed> $config
     *   The rules.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);

        $this->edgeSignalMap = EdgeSignalMap::fromMetadata($metadata);

        $this->getLogger()->debug('EdgeSignal reading signals from edge headers', [
            'plugin' => $this->getName(),
            'provider' => $this->edgeSignalMap->provider(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'Edge Signals';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Match on the TLS fingerprint and bot score a CDN computed at the edge';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        if (!$this->edgeIsTrusted($request)) {
            $this->warnEdgeIsUntrusted($request, 'EdgeSignal', [
                'provider' => $this->edgeSignalMap->provider(),
            ]);

            return false;
        }

        $this->signals = $this->edgeSignalMap->read($request);

        if ($this->signals === []) {
            // Through the edge, and it sent none of them. On Cloudflare that
            // is a Managed Transform nobody enabled, which is silent in every
            // other way -- the rules simply never match.
            $this->getLogger()->debug('EdgeSignal edge headers carried nothing', $this->getContext($request, [
                'provider' => $this->edgeSignalMap->provider(),
            ]));

            return false;
        }

        try {
            $result = $this->evaluateRequest($request, $this->config);
        } finally {
            $this->signals = [];
        }

        if ($result) {
            $this->getLogger()->info('EdgeSignal matched', $this->getContext($request, [
                'provider' => $this->edgeSignalMap->provider(),
            ]));
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * Resolved from what the edge sent, and **only** from that. A rule naming
     * a signal the edge did not send gets NULL rather than a value from
     * somewhere else, because "the transform is off" and "the score is zero"
     * have to be distinguishable -- they are opposite answers on Cloudflare's
     * scale.
     */
    protected function getValue(Request $request, string $variable): mixed
    {
        return $this->signals[strtolower(trim($variable))] ?? null;
    }

    /**
     * {@inheritdoc}
     *
     * The signal names, so a misspelled rule is reported at construction
     * rather than matching nothing for a year (#165).
     */
    protected function knownRuleVariables(): array
    {
        return EdgeSignalMap::FIELDS;
    }
}
