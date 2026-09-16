<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Metrics;

use Kanopi\Firewall\Event\ChallengeFailed;
use Kanopi\Firewall\Event\ChallengeSolved;
use Kanopi\Firewall\Event\DecisionEvent;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Event\RequestBlocked;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Event\RequestRecorded;
use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\Firewall\Plugins\PluginInterface;

/**
 * Turns decisions into counters (#222).
 *
 * The interesting part of an exporter is not the socket -- that is twenty lines
 * -- it is deciding what the series *are*, so that two installations produce the
 * same ones. This is that decision, in one place, with `Metric` holding the
 * names.
 *
 * ## Wiring it up
 *
 * PSR-14 dispatchers match on the concrete event class, so registering this for
 * `DecisionEvent` catches nothing. `eventClasses()` is the list to loop over:
 *
 * ```php
 * $listener = new DecisionMetricsListener(new StatsdRecorder('127.0.0.1'));
 *
 * foreach (DecisionMetricsListener::eventClasses() as $event) {
 *     $dispatcher->addListener($event, $listener);
 * }
 * ```
 *
 * ## Cardinality is capped here rather than trusted
 *
 * `rule` comes from configuration and is bounded in every sane setup, which is
 * exactly the kind of statement that is true until somebody generates rules
 * from a database. The cap is not a substitute for choosing bounded labels --
 * `Metric` explains why nothing derived from the request is one -- it is the
 * thing that means a mistake costs a vague dashboard rather than a dead
 * Prometheus server.
 */
final class DecisionMetricsListener
{
    /**
     * Distinct rule names admitted before the rest are bucketed.
     *
     * Generous for a hand-written configuration and far below the point at
     * which a time-series database minds. A deployment legitimately past this
     * has more rules than a `rule` label can usefully distinguish anyway.
     */
    public const DEFAULT_RULE_LIMIT = 200;

    /**
     * Rule names already admitted, as a set.
     *
     * @var array<string, true>
     */
    private array $seenRules = [];

    /**
     * @param MetricsRecorderInterface $metricsRecorder
     *   Where the numbers go.
     * @param int $ruleLimit
     *   Distinct `rule` label values to admit before bucketing the rest into
     *   `Metric::OVERFLOW`. Zero removes the cap, for a deployment that has
     *   measured its own rule count and would rather see all of them.
     */
    public function __construct(
        private readonly MetricsRecorderInterface $metricsRecorder,
        private readonly int $ruleLimit = self::DEFAULT_RULE_LIMIT,
    ) {
    }

    /**
     * Every event this listens for.
     *
     * @return array<int, class-string<DecisionEvent>>
     *   Class names, for registering against a PSR-14 dispatcher.
     */
    public static function eventClasses(): array
    {
        return [
            RequestAllowed::class,
            RequestBlocked::class,
            RequestChallenged::class,
            RequestRecorded::class,
            RequestRedirected::class,
            RequestMarked::class,
            ChallengeSolved::class,
            ChallengeFailed::class,
        ];
    }

    /**
     * Count one decision.
     *
     * @param DecisionEvent $decisionEvent
     *   The decision.
     */
    public function __invoke(DecisionEvent $decisionEvent): void
    {
        match (true) {
            $decisionEvent instanceof ChallengeSolved => $this->challenge($decisionEvent->getProvider(), 'solved'),
            $decisionEvent instanceof ChallengeFailed => $this->failure($decisionEvent),
            default => $this->decision($decisionEvent),
        };
    }

    /**
     * Count a terminal decision about a request.
     *
     * @param DecisionEvent $decisionEvent
     *   The decision.
     */
    private function decision(DecisionEvent $decisionEvent): void
    {
        $decision = match (true) {
            $decisionEvent instanceof RequestAllowed => 'allowed',
            $decisionEvent instanceof RequestBlocked => 'blocked',
            $decisionEvent instanceof RequestChallenged => 'challenged',
            $decisionEvent instanceof RequestRecorded => 'recorded',
            $decisionEvent instanceof RequestRedirected => 'redirected',
            $decisionEvent instanceof RequestMarked => 'marked',
            // A decision event this release does not know about. Counted rather
            // than dropped: a listener that silently ignores a new event type
            // is a dashboard that quietly stops adding up.
            default => Metric::OVERFLOW,
        };

        // `enforced` is passed through exactly as the event reports it, which
        // means `recorded` and `marked` always read `enforced="false"`: both
        // let the request through -- one writes to the block list, the other
        // annotates -- so neither enforced anything, and their events say so.
        //
        // That is coherent rather than a quirk to paper over. Filtering
        // `enforced="true"` gives what the firewall *did to* traffic, and
        // recording and marking are not among those things. It does mean
        // `enforced` cannot tell a `mode: log` dry run from a real one on those
        // two buckets, which is a property of the events rather than of this.
        $this->metricsRecorder->increment(Metric::REQUESTS, [
            'decision' => $decision,
            'rule' => $this->ruleLabel($decisionEvent),
            'enforced' => $decisionEvent->isEnforced() ? Metric::ENFORCED : Metric::OBSERVED,
        ]);

        // A challenge served is the denominator of the solve rate, and it has
        // to be counted where it happens: `ChallengeSolved` only ever fires for
        // the visitors who came back.
        if ($decisionEvent instanceof RequestChallenged) {
            $this->challenge($decisionEvent->getProvider(), 'issued');
        }
    }

    /**
     * Count a refused challenge submission, and why.
     *
     * @param ChallengeFailed $challengeFailed
     *   The failure.
     */
    private function failure(ChallengeFailed $challengeFailed): void
    {
        $this->challenge($challengeFailed->getProvider(), 'failed');

        $this->metricsRecorder->increment(Metric::CHALLENGE_FAILURES, [
            'provider' => $this->label($challengeFailed->getProvider()),
            'reason' => $this->label($challengeFailed->getReason()),
        ]);
    }

    /**
     * Count one challenge outcome.
     *
     * @param string $provider
     *   The provider name.
     * @param string $outcome
     *   `issued`, `solved` or `failed`.
     */
    private function challenge(string $provider, string $outcome): void
    {
        $this->metricsRecorder->increment(Metric::CHALLENGES, [
            'provider' => $this->label($provider),
            'outcome' => $outcome,
        ]);
    }

    /**
     * The `rule` label for a decision.
     *
     * @param DecisionEvent $decisionEvent
     *   The decision.
     *
     * @return string
     *   A rule name, `Metric::NO_RULE`, or `Metric::OVERFLOW`.
     */
    private function ruleLabel(DecisionEvent $decisionEvent): string
    {
        $plugin = method_exists($decisionEvent, 'getPlugin') ? $decisionEvent->getPlugin() : null;

        if (!$plugin instanceof PluginInterface) {
            return Metric::NO_RULE;
        }

        $name = $this->label($plugin->getName());

        if ($name === Metric::NO_RULE) {
            return $name;
        }

        if (isset($this->seenRules[$name])) {
            return $name;
        }

        if ($this->ruleLimit > 0 && count($this->seenRules) >= $this->ruleLimit) {
            return Metric::OVERFLOW;
        }

        $this->seenRules[$name] = true;

        return $name;
    }

    /**
     * Make a value safe to use as a label.
     *
     * Trimmed, and emptiness turned into something nameable. An empty label
     * value is indistinguishable from an absent one in most backends, which
     * turns "this rule has no name" into "this series is about nothing".
     *
     * @param string $value
     *   The raw value.
     *
     * @return string
     *   The label value.
     */
    private function label(string $value): string
    {
        $value = trim($value);

        return $value === '' ? Metric::NO_RULE : $value;
    }
}
