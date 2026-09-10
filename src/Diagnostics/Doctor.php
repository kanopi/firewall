<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Diagnostics;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\DatabaseConsumers;
use Kanopi\Firewall\Utility\PanicSwitch;
use Symfony\Component\HttpFoundation\Request;

/**
 * Look at a real environment and say what is wrong with it.
 *
 * 2.22.0 added three ways to ask the firewall about its own health and nothing surfaced
 * any of them, so every integration that wanted a status page had to write the same code
 * (#211). This is that code, once.
 *
 * ## What it is not
 *
 * Not a config linter. It runs against the environment it is in -- opening the storage
 * file, reaching the database, reading the GeoIP database's mtime -- so the same
 * configuration diagnoses differently on a laptop and in production, which is the point.
 * Whether a rule can ever match is a static question and belongs to the linter (#216).
 *
 * ## It builds things
 *
 * Constructing a plugin is what opens its storage connection, so reachability is tested
 * rather than assumed, and constructing a database consumer creates its table if absent.
 * That is the right behaviour for a diagnosis and the wrong behaviour for a request path.
 * **Nothing here should be called from one.**
 */
class Doctor
{
    /**
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Configuration sources, as `Firewall::create()` takes them.
     */
    public function __construct(private readonly array $configs)
    {
    }

    /**
     * Examine the environment.
     *
     * @return array<int, Diagnosis>
     *   Every finding, in the order they were looked at: whether the config
     *   loaded first, because nothing below it means much otherwise.
     */
    public function run(): array
    {
        $findings = [];

        Config::clearLoadErrors();
        $config = Config::load($this->configs);

        $findings = $this->checkConfig($config);

        $global = is_array($config['global'] ?? null) ? $config['global'] : [];

        $findings[] = $this->checkTrustedProxies($global);

        $findings[] = $this->checkPanicSwitch($global);

        // Before `checkRules()`, and that ordering is load-bearing. Building a
        // rule is what fetches its sources, so asking afterwards would report
        // the cache this command had just warmed rather than the one it found
        // -- and "never been fetched" could never be reported at all.
        foreach ($this->checkSources($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkRules() as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkSchema($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkStorage($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkGeoIp($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        return $findings;
    }

    /**
     * How many findings there are at each status.
     *
     * @param array<int, Diagnosis> $findings
     *   The findings.
     *
     * @return array{ok: int, warning: int, error: int}
     *   Counts.
     */
    public static function tally(array $findings): array
    {
        $tally = [Diagnosis::OK => 0, Diagnosis::WARNING => 0, Diagnosis::ERROR => 0];

        foreach ($findings as $finding) {
            $tally[$finding->status]++;
        }

        return $tally;
    }

    /**
     * Did the configuration load, and did anything degrade on the way.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkConfig(array $config): array
    {
        $findings = [];

        foreach (Config::getLoadErrors() as $error) {
            // An error rather than a warning even though the firewall starts:
            // a file that did not load is a set of rules that is not running,
            // and the operator wrote them expecting otherwise.
            $findings[] = Diagnosis::error(
                'Config file failed to load: ' . $error['file'],
                $error['message'],
                'configuration/loading-and-includes.md'
            );
        }

        foreach (Config::getLoadWarnings() as $warning) {
            $findings[] = Diagnosis::warning(
                'Config loaded with a warning: ' . $warning['file'],
                $warning['message'],
                'configuration/loading-and-includes.md'
            );
        }

        if ($findings === []) {
            $plugins = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];

            $findings[] = Diagnosis::ok(
                'Config loads',
                sprintf('%d rule%s configured', count($plugins), count($plugins) === 1 ? '' : 's')
            );
        }

        return $findings;
    }

    /**
     * Whether the client IP can be trusted.
     *
     * The sharpest edge in the product: get it wrong and every IP rule, allow
     * list and per-IP rate limit is spoofable through `X-Forwarded-For`.
     *
     * **And the one thing this command cannot settle from a terminal.**
     * `Request::setTrustedProxies()` is called by the host application's
     * bootstrap -- a `settings.php`, a middleware, a `functions.php` -- and a
     * CLI process runs none of that. So a correctly configured site would be
     * reported as unconfigured on every run.
     *
     * Rather than emit a confident false positive on the most important check
     * it has, this says what it can see and what it cannot. Run through a web
     * SAPI, where the bootstrap has run, it answers properly.
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @return Diagnosis
     *   The finding.
     */
    private function checkTrustedProxies(array $global): Diagnosis
    {
        $trusted = Request::getTrustedProxies();

        if ($trusted !== []) {
            return Diagnosis::ok(
                'Trusted proxies configured',
                sprintf('%d range%s trusted', count($trusted), count($trusted) === 1 ? '' : 's')
            );
        }

        $asserted = $global['behind_proxy'] ?? null;
        $required = (bool) ($global['require_trusted_proxies'] ?? false);

        if ($this->isCommandLine()) {
            $detail = 'Request::setTrustedProxies() is called by your application bootstrap, which a '
                . 'command-line process does not run — so this cannot be checked from here. '
                . 'Config asserts behind_proxy: '
                . ($asserted === null ? 'unset' : var_export($asserted, true))
                . ($required ? ' with require_trusted_proxies: true, so the firewall will refuse to start without them.' : '.');

            // A warning even when the config looks right, because "unverified"
            // is the honest status and an operator reading `ok` here would take
            // it as confirmation the site is not spoofable.
            return Diagnosis::warning(
                'Trusted proxies could not be verified from the command line',
                $detail,
                'configuration/global.md#trusted-proxies'
            );
        }

        if ($asserted === true) {
            return Diagnosis::error(
                'Trusted proxies not configured, and behind_proxy asserts there is one',
                'Every IP-based rule can be bypassed with a forged X-Forwarded-For header. '
                . 'Call Request::setTrustedProxies() with your proxy CIDRs before Firewall::create().',
                'configuration/global.md#trusted-proxies'
            );
        }

        return Diagnosis::warning(
            'No trusted proxies configured',
            'Correct if nothing sits in front of this application. If a CDN or load balancer does, '
            . 'every IP-based rule can be bypassed with a forged X-Forwarded-For header.',
            'configuration/global.md#trusted-proxies'
        );
    }

    /**
     * Whether somebody is holding the panic switch down.
     *
     * The switch is a file, so it leaves no trace in the configuration and no
     * trace in a deploy log. Three weeks after an incident the only evidence
     * that the firewall is still in `log` is a warning in a log nobody is
     * reading and this line (#207).
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @return Diagnosis
     *   The finding.
     */
    private function checkPanicSwitch(array $global): Diagnosis
    {
        $panic = PanicSwitch::read($global['panic_file'] ?? null);

        if ($panic['problem'] !== null) {
            return Diagnosis::error(
                'Panic file is present but is not being applied',
                sprintf('%s %s. The firewall is running in its configured mode.', $panic['path'], $panic['problem']),
                'configuration/global.md#panic-switch'
            );
        }

        if ($panic['active'] && $panic['mode'] instanceof FirewallMode) {
            $configured = FirewallMode::tryFrom(is_string($global['mode'] ?? null) ? $global['mode'] : 'block')
                ?? FirewallMode::Block;

            // Warning rather than error: somebody meant to do this. It is loud
            // because the thing that goes wrong is forgetting, not flipping.
            return Diagnosis::warning(
                sprintf('Panic switch is ACTIVE — running in %s, not %s', $panic['mode']->value, $configured->value),
                sprintf('Delete %s to restore the configured mode. Takes effect on the next request.', $panic['path']),
                'configuration/global.md#panic-switch'
            );
        }

        if ($panic['path'] === null) {
            return Diagnosis::ok(
                'No panic switch configured',
                'Set global.panic_file to be able to change the mode during an incident without a deploy.'
            );
        }

        return Diagnosis::ok('Panic switch is off', $panic['path'] . ' does not exist');
    }

    /**
     * How long a rule source may go unrefreshed before it is an error.
     *
     * **Off unless asked for.** 2.23.1 made the report say *how* stale a source is
     * rather than only that it is (#297) and stopped there, because turning a warning
     * into an error changes an exit code. Defaulting this on would do exactly that on
     * upgrade: a deploy that passed yesterday fails today, over a source that was
     * already stale yesterday and that nothing has done anything about. Whether an old
     * rule list should stop a deploy is the operator's call about their own refresh
     * cycle, and a library is in no position to guess it.
     *
     * So it is opt-in, and the useful thing this can do is make it one line:
     *
     * ```yaml
     * global:
     *   stale_source_error_after: 604800   # a week
     * ```
     *
     * The bound is absolute rather than a multiple of each source's ttl, because a
     * multiple gets the short ones wrong in the dangerous direction: ten times a
     * 60-second ttl is ten minutes, and a ten-minute-old rule list is not an incident.
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @return int
     *   Seconds, or 0 when the escalation is off -- which is the default, and also
     *   what an unusable value falls back to. `checkSources()` reports that value
     *   rather than letting it pass as a deliberate 0.
     */
    private function staleSourceErrorAfter(array $global): int
    {
        $configured = $global['stale_source_error_after'] ?? null;

        if (!is_numeric($configured)) {
            return 0;
        }

        return max(0, (int) $configured);
    }

    /**
     * Whether this is running from a terminal.
     *
     * A seam, and the only one here. The trusted-proxy check answers
     * differently depending on it -- from a terminal it cannot verify anything,
     * because the host application's bootstrap has not run -- and the branch
     * that matters most is the one a test process can never reach, since the
     * suite is the CLI SAPI by definition.
     *
     * Overriding this is how the web-context branches get exercised. Reading
     * `PHP_SAPI` inline instead would leave the error case for a spoofable
     * production site as the least-tested path in the file.
     *
     * @return bool
     *   TRUE when running under the CLI SAPI.
     */
    protected function isCommandLine(): bool
    {
        return PHP_SAPI === 'cli';
    }

    /**
     * Rules that are not running, and backends running blind.    /**
     * Rules that are not running, and backends running blind.
     *
     * The two questions 2.22.0 taught the firewall to answer, and the reason
     * this command exists.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkRules(): array
    {
        try {
            $firewall = Firewall::create($this->configs);
        } catch (\Throwable $throwable) {
            // `\Throwable`, not `\Exception`. `create()` is documented to throw
            // ConfigurationException for a wiring the firewall refuses to start
            // with -- an empty challenge secret, a provider that does not
            // resolve -- and in production that is a fatal at boot, so it is an
            // error here either way.
            //
            // But it also has paths out through `\Error`: a non-map entry in
            // `plugins:` reaches a usort() comparator typed `array` and leaves
            // as a TypeError (#281). A diagnostic is run *because* a config is
            // suspect, so it is the last thing that should fatal on one.
            return [Diagnosis::error(
                'The firewall refuses to start with this configuration',
                $throwable->getMessage(),
                'reference/error-handling.md'
            )];
        }

        $findings = [];

        foreach ($firewall->getFailedRules() as $rule) {
            $findings[] = Diagnosis::error(
                sprintf('Rule %s is not running', $rule['plugin']),
                sprintf('Configured as a %s rule. Its constructor said: %s', $rule['bucket'], $rule['error']),
                'reference/error-handling.md#checking-that-every-rule-is-running'
            );
        }

        foreach ($firewall->getDegradedBackends() as $backend) {
            $findings[] = Diagnosis::error(
                sprintf('The %s is running without its store', $backend['component']),
                sprintf('%s could not be reached: %s', $backend['backend'], $backend['error']),
                'reference/error-handling.md#checking-that-a-backend-can-reach-its-server'
            );
        }

        if ($findings === []) {
            $findings[] = Diagnosis::ok('Every configured rule is running');
        }

        return $findings;
    }

    /**
     * Tables behind the schema this release declares.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkSchema(array $config): array
    {
        $built = DatabaseConsumers::fromConfig($config);
        $findings = [];

        foreach ($built['failures'] as $failure) {
            $findings[] = Diagnosis::error(
                'Database for ' . $failure['label'] . ' could not be reached',
                $failure['error'],
                'how-to/schema-migrations.md'
            );
        }

        $behind = 0;

        foreach ($built['consumers'] as $label => $consumer) {
            /** @var array<int, array{table: string, kind: string, name: string}> $pending */
            $pending = $consumer->pendingSchemaChanges();

            if ($pending === []) {
                continue;
            }

            $behind++;
            $findings[] = Diagnosis::warning(
                sprintf('Table for %s is behind the declared schema', $label),
                sprintf(
                    'Missing %s. Run bin/firewall-migrate to add them.',
                    implode(', ', array_map(
                        static fn(array $c): string => $c['kind'] . ' ' . $c['name'],
                        $pending
                    ))
                ),
                'how-to/schema-migrations.md'
            );
        }

        if ($built['consumers'] !== [] && $behind === 0 && $built['failures'] === []) {
            $findings[] = Diagnosis::ok(
                'Database schema is current',
                sprintf('%d consumer%s checked', count($built['consumers']), count($built['consumers']) === 1 ? '' : 's')
            );
        }

        return $findings;
    }

    /**
     * Whether a file-backed store can actually be written.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkStorage(array $config): array
    {
        $storage = is_array($config['storage'] ?? null) ? $config['storage'] : [];
        $settings = is_array($storage['config'] ?? null) ? $storage['config'] : [];
        $findings = [];

        foreach (['storage_file', 'offense_file'] as $key) {
            $path = $settings[$key] ?? null;
            if (!is_string($path)) {
                continue;
            }

            if ($path === '') {
                continue;
            }

            // The directory, not the file: the file is created on first write,
            // so its absence is normal and the directory's is not.
            $directory = dirname($path);

            if (!is_dir($directory)) {
                $findings[] = Diagnosis::error(
                    sprintf('Storage directory for %s does not exist', $key),
                    $directory,
                    'configuration/storage.md'
                );

                continue;
            }

            if (!is_writable($directory) || (is_file($path) && !is_writable($path))) {
                $findings[] = Diagnosis::error(
                    sprintf('Storage path for %s is not writable', $key),
                    $path,
                    'configuration/storage.md'
                );

                continue;
            }

            $findings[] = Diagnosis::ok(sprintf('Storage path writable (%s)', $key), $path);
        }

        return $findings;
    }

    /**
     * Whether the GeoIP databases are present, and how old they are.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkGeoIp(array $config): array
    {
        $findings = [];

        foreach ($this->pluginMetadata($config) as $metadata) {
            $reader = is_array($metadata['reader'] ?? null) ? $metadata['reader'] : [];
            $database = $reader['db'] ?? null;
            if (!is_string($database)) {
                continue;
            }

            if ($database === '') {
                continue;
            }

            if (!is_file($database)) {
                $findings[] = Diagnosis::error(
                    'GeoIP database not found',
                    $database . ' — every rule reading location or ASN will not match.',
                    'how-to/geoip-setup.md'
                );

                continue;
            }

            $days = (int) floor((time() - (int) filemtime($database)) / 86400);

            // Warning rather than error: a stale database still answers, it just
            // answers with allocations that have since moved. MaxMind publishes
            // twice a week, so a month is well past routine.
            $findings[] = $days > 30
                ? Diagnosis::warning(
                    sprintf('GeoIP database is %d days old', $days),
                    $database . ' — addresses reassigned since then resolve to the wrong place.',
                    'how-to/geoip-setup.md'
                )
                : Diagnosis::ok(sprintf('GeoIP database is %d days old', $days), $database);
        }

        return $findings;
    }

    /**
     * Whether configured rule sources have been fetched, and how stale they are.
     *
     * Reads the cache rather than fetching. A diagnosis that went to the
     * network would report on the network as much as on the configuration, and
     * would be slow enough that nobody ran it.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkSources(array $config): array
    {
        $sourceCache = new SourceCache();
        $sourceManager = new SourceManager();
        $fresh = 0;
        $findings = [];
        $global = is_array($config['global'] ?? null) ? $config['global'] : [];
        $errorAfter = $this->staleSourceErrorAfter($global);

        // Set, and not a number. Silently falling back to "off" would be the
        // worst of both: the operator asked for a gate, believes they have one,
        // and does not. `stale_source_error_after: "30 days"` is the shape of
        // it, and YAML will happily hand that over as a string.
        if (array_key_exists('stale_source_error_after', $global) && !is_numeric($global['stale_source_error_after'])) {
            $findings[] = Diagnosis::warning(
                'global.stale_source_error_after is not a number of seconds',
                sprintf(
                    'Read as %s, so no source will be escalated to an error. Give it seconds, or 0 to turn it off deliberately.',
                    var_export($global['stale_source_error_after'], true)
                ),
                'configuration/global.md#stale-rule-sources'
            );
        }

        foreach ($this->pluginMetadata($config) as $metadata) {
            $sources = is_array($metadata['sources'] ?? null) ? $metadata['sources'] : [];

            if ($sources === []) {
                continue;
            }

            try {
                // Asked of SourceManager rather than parsed here: it already
                // handles the bare-string shorthand and rejects a malformed
                // declaration, and a second parser would drift from the one
                // that actually loads the rules.
                $definitions = $sourceManager->definitions($sources);
            } catch (\Exception $exception) {
                $findings[] = Diagnosis::error(
                    'Rule source declaration is not valid',
                    $exception->getMessage(),
                    'configuration/sources.md'
                );

                continue;
            }

            foreach ($definitions as $definition) {
                $url = $definition->upstream->url;
                $meta = $sourceCache->meta($definition);

                if ($meta === []) {
                    $findings[] = Diagnosis::warning(
                        'Rule source has never been fetched',
                        $url . ' — run bin/firewall-sources, or the first request that needs it fetches it inline.',
                        'how-to/syncing-sources.md'
                    );

                    continue;
                }

                if (!$sourceCache->isFresh($definition, $meta)) {
                    $fetchedAt = $meta['fetched_at'] ?? null;

                    if (!is_int($fetchedAt)) {
                        // A cache entry carrying no fetch time is *why* this
                        // reads as stale, rather than something that happens to
                        // also be stale, so it is worth saying instead of
                        // reporting an age of zero -- and it cannot be aged, so
                        // the escalation below has nothing to measure.
                        $findings[] = Diagnosis::warning(
                            'Rule source cache is stale',
                            sprintf('%s — its cache entry records no fetch time, so it cannot be trusted as current.', $url),
                            'how-to/syncing-sources.md'
                        );

                        continue;
                    }

                    // How stale, not just that it is stale. One second past the
                    // ttl is a refresh that has not run yet; a week past it is a
                    // fetcher that has been failing since last Monday, and the
                    // operator does something different about each (#297).
                    $age = time() - $fetchedAt;
                    $detail = sprintf(
                        '%s — last fetched %s ago, past its ttl of %ds.',
                        $url,
                        $this->describeAge($age),
                        $sourceCache->ttl($definition)
                    );

                    if ($errorAfter > 0 && $age >= $errorAfter) {
                        $findings[] = Diagnosis::error(
                            'Rule source has not refreshed in a long time',
                            $detail . sprintf(
                                ' Past the %s you set as global.stale_source_error_after, this is a sync that has'
                                . ' stopped working rather than one that has not run yet: the rule is still matching,'
                                . ' on a list nobody has updated since. Raise that value, or set it to 0, to stop this'
                                . ' failing a deploy.',
                                $this->describeAge($errorAfter)
                            ),
                            'how-to/syncing-sources.md'
                        );

                        continue;
                    }

                    $findings[] = Diagnosis::warning('Rule source cache is stale', $detail, 'how-to/syncing-sources.md');

                    continue;
                }

                $fresh++;
            }
        }

        if ($fresh > 0) {
            $findings[] = Diagnosis::ok(sprintf('%d rule source%s cached and fresh', $fresh, $fresh === 1 ? '' : 's'));
        }

        return $findings;
    }

    /**
     * An age a person can read at a glance.
     *
     * Seconds are the honest unit and an unreadable one: `137882s` is a number
     * to be divided rather than a fact to be acted on. The units step up so the
     * magnitude is obvious at whatever scale the answer lands, which is the
     * whole point of reporting it.
     *
     * Rounded down, so nothing is ever described as older than it is -- but
     * hours run to two days rather than one before days take over. A cache
     * fetched 38 hours ago reads as `38 hours`, where rounding to the larger
     * unit would call it `1 day` and understate it by better than a third. The
     * one-to-three day range is exactly where an operator decides whether this
     * is a refresh that has not run or an outage, so it is the range that must
     * not be blurred.
     *
     * @param int $seconds
     *   Age in seconds.
     *
     * @return string
     *   For example `38 hours`.
     */
    private function describeAge(int $seconds): string
    {
        $seconds = max(0, $seconds);

        // Threshold and divisor are separate: days do not start until two of
        // them have passed, but are still counted in 86400s. Folding the two
        // together made three days report as "one day".
        $scales = [
            ['from' => 172800, 'per' => 86400, 'unit' => 'day'],
            ['from' => 3600, 'per' => 3600, 'unit' => 'hour'],
            ['from' => 60, 'per' => 60, 'unit' => 'minute'],
        ];

        foreach ($scales as $scale) {
            if ($seconds < $scale['from']) {
                continue;
            }

            $count = intdiv($seconds, $scale['per']);

            return sprintf('%d %s%s', $count, $scale['unit'], $count === 1 ? '' : 's');
        }

        return sprintf('%d second%s', $seconds, $seconds === 1 ? '' : 's');
    }

    /**
     * Every plugin's metadata block.    /**
     * Every plugin's metadata block.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, array<string, mixed>>
     *   One metadata array per configured plugin that has one.
     */
    private function pluginMetadata(array $config): array
    {
        $plugins = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];
        $metadata = [];

        foreach ($plugins as $plugin) {
            if (!is_array($plugin)) {
                continue;
            }

            if (is_array($plugin['metadata'] ?? null)) {
                $metadata[] = $plugin['metadata'];
            }
        }

        return $metadata;
    }
}
