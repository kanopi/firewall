<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Metrics;

/**
 * The metric and label names this library emits (#222).
 *
 * Fixed, and fixed on purpose. The value of shipping exporters rather than
 * leaving everybody to write their own is that two installations produce the
 * same series, so a dashboard, an alert or a support conversation means the
 * same thing on both. A name an operator can choose is a name that has to be
 * agreed before anyone can compare anything.
 *
 * ## Every label here is bounded, and that is the design constraint
 *
 * `rule` comes from configuration and `provider` from a fixed set; `decision`,
 * `outcome`, `reason` and `enforced` are enumerations. Nothing derived from a
 * request is a label -- not the client address, not the path, not the user
 * agent. The obvious first draft of a firewall exporter labels by client IP,
 * and that is the draft that takes a Prometheus server down: one series per
 * address, forever, on the component that exists to be hit by addresses you did
 * not expect.
 *
 * The answers those labels would give live in the decision log
 * (`DatabaseHandler`, #181), where a row per decision is a query rather than a
 * time series.
 */
final class Metric
{
    /**
     * Every terminal decision, by what was decided and which rule decided it.
     *
     * Labels: `decision`, `rule`, `enforced`.
     */
    public const REQUESTS = 'firewall_requests_total';

    /**
     * Challenges issued, solved and failed.
     *
     * Labels: `provider`, `outcome`.
     *
     * Issued against solved is the ratio the issue asks for: a rule whose
     * challenges are never solved is either working perfectly or catching only
     * bots that never retry, and one number cannot tell those apart.
     */
    public const CHALLENGES = 'firewall_challenges_total';

    /**
     * Why a challenge submission was refused.
     *
     * Labels: `provider`, `reason`.
     *
     * Separate from the outcome counter because `reason` is only meaningful on
     * a failure, and a label that is empty for two thirds of a series is a
     * label that makes every query harder.
     */
    public const CHALLENGE_FAILURES = 'firewall_challenge_failures_total';

    /**
     * A decision the firewall acted on.
     */
    public const ENFORCED = 'true';

    /**
     * A decision `mode: log` recorded without acting on it.
     */
    public const OBSERVED = 'false';

    /**
     * Stands in for a rule when no rule was responsible.
     *
     * A request allowed by default, or blocked by the storage block list rather
     * than by a rule that matched now. An empty label would be indistinguishable
     * from a rule whose name is missing, which is a different problem.
     */
    public const NO_RULE = 'none';

    /**
     * Stands in for a label the cardinality cap refused to admit.
     *
     * Counted rather than dropped: a series that stops incrementing looks like
     * traffic that stopped, and the distinction between "nothing is happening"
     * and "I stopped telling you" is the whole reason this value exists.
     */
    public const OVERFLOW = 'other';
}
