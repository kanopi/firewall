<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Exception\ReputationUnavailableException;

/**
 * A provider that can score more than the client address (#341).
 *
 * Separate from `ReputationProviderInterface` for the reason every other opt-in
 * interface in this library is separate: `ObserveModeInterface`,
 * `ScheduledRuleInterface` and `IdentityVerificationInterface` all exist
 * because adding a method to the interface everyone implements makes every
 * implementation written against the documented guide **fatally incomplete on a
 * `composer update`**. `ReputationProviderInterface` shipped in 2.27.0 with a
 * page telling people how to write one; widening its signature a release later
 * would break anybody who did.
 *
 * So the address-only contract stays exactly as it was, and a provider that can
 * answer about an email address or a username says so by implementing this too.
 * `AbuseIpdbProvider` does not, and should not: AbuseIPDB scores addresses.
 *
 * A rule configured with `subject:` naming something its provider does not
 * handle refuses to start, rather than sending a username to a service that
 * will answer something about it anyway.
 */
interface SubjectAwareReputationProviderInterface extends ReputationProviderInterface
{
    /**
     * Whether this provider can answer about a subject at all.
     *
     * Asked once, when the rule is built, so a mismatch is a startup failure
     * rather than a warning on every request. Distinct from
     * `knowsAbout()`, which is asked per request about a particular value --
     * this is about the *kind*.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject a rule is configured to look up.
     *
     * @return bool
     *   TRUE when this provider scores that kind of thing.
     */
    public function handles(ReputationSubject $reputationSubject): bool;

    /**
     * Look up one subject.
     *
     * @param ReputationSubject $reputationSubject
     *   What to ask about.
     *
     * @return ReputationVerdict
     *   What the provider said.
     *
     * @throws ReputationUnavailableException
     *   When no answer could be obtained, for any reason. The rule treats every
     *   one of them the same way: log, cache briefly, carry on.
     */
    public function checkSubject(ReputationSubject $reputationSubject): ReputationVerdict;
}
