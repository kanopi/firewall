<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Reputation\ReputationVerdict;

/**
 * Check the client IP's reputation against AbuseIPDB.
 *
 * AbuseIPDB scores an address 0-100 by how confidently it has been reported
 * for abuse. This rule matches when that confidence reaches `threshold`, so
 * with `response: block` a known-bad address is rejected before the expensive
 * rule-matching plugins ever run.
 *
 * ## It is `Reputation` with the provider fixed
 *
 * Everything general about a reputation lookup -- the caching, the threshold,
 * the fail-open posture, the failure policy -- moved into `Reputation` when the
 * provider interface was extracted (#204), and the AbuseIPDB specifics moved
 * into `Reputation\AbuseIpdbProvider`. **Nothing about this rule's
 * configuration or behaviour changed**: `api_key`, `threshold`, `cache_ttl`,
 * `error_cache_ttl`, `max_age_in_days`, `timeout`, `cache_dir`, `block_status`
 * and `block_duration` all still live where they did, the cache is still
 * written to the same files in the same directory, and the class stays because
 * `plugin: "Kanopi\\Firewall\\Plugins\\AbuseIpdb"` is in configurations this
 * library does not own.
 *
 * Three behaviours are worth knowing before enabling it.
 *
 * **It fails open.** A lookup that times out, is refused, or runs into a spent
 * quota reports no match, logs at warning level, and lets evaluation continue.
 * Reputation is corroborating evidence, not the last line of defence -- a
 * third-party outage must not become an outage here. Nothing here blocks a
 * request it could not get an answer for.
 *
 * **It is cached, because the quota is small.** The free tier allows 1,000
 * checks a day, which a modest site would burn through before lunch if every
 * request meant a call. Verdicts are cached per address for `cache_ttl` (24h by
 * default), so cost is one call per unique visitor per day; repeat visitors and
 * crawlers are free. Failures are cached too, for a much shorter
 * `error_cache_ttl`.
 *
 * **It never calls the API for an address that cannot be in the database.**
 * Private and reserved ranges are skipped, so a local or intranet deployment
 * spends no quota at all.
 *
 * Addresses AbuseIPDB marks as whitelisted -- search-engine crawlers and
 * similar known-good infrastructure -- never match, whatever their score.
 *
 * Requires an API key from https://www.abuseipdb.com/account/api. With no
 * `api_key` the rule is a no-op that matches nothing, so adding it to a config
 * before the key is provisioned is safe.
 */
class AbuseIpdb extends Reputation
{
    /**
     * {@inheritdoc}
     */
    protected function defaultName(): string
    {
        return 'AbuseIPDB';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Check the client IP address reputation against AbuseIPDB and match when its abuse confidence reaches the configured threshold';
    }

    /**
     * {@inheritdoc}
     *
     * The whole of what this subclass is. `config.provider` still wins, so
     * somebody who wants AbuseIPDB's name on a rule that asks something else
     * can have it, but nobody has to write a provider to keep an existing
     * configuration working.
     */
    protected function defaultProvider(): string
    {
        return 'abuseipdb';
    }

    /**
     * {@inheritdoc}
     *
     * Verdicts cached before 2.27.0 were written as
     * `{"report": {"abuse_confidence_score": 100, "is_whitelisted": false}}`,
     * and the file names have not changed. Reading them keeps an upgrade from
     * spending a day's quota re-asking about addresses this firewall already
     * had answers for -- 1,000 checks is not a budget to pay twice for the
     * same information, and a cache miss storm is a slow morning rather than a
     * visible failure, which is the kind that goes undiagnosed.
     *
     * Entries written from now on use the shared shape, so this reads and never
     * writes. It can go when nobody is upgrading from before 2.27.0.
     */
    protected function legacyVerdict(array $entry): ?ReputationVerdict
    {
        $report = $entry['report'] ?? null;

        if (!is_array($report) || !isset($report['abuse_confidence_score'])) {
            return null;
        }

        return new ReputationVerdict(
            (float) (int) $report['abuse_confidence_score'],
            (bool) ($report['is_whitelisted'] ?? false),
            [
                'abuse_confidence_score' => (int) $report['abuse_confidence_score'],
                'total_reports' => (int) ($report['total_reports'] ?? 0),
                'country_code' => (string) ($report['country_code'] ?? ''),
            ]
        );
    }
}
