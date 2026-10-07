<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Diagnostics;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Plugins\AbstractPluginBase;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Storage\RecordedRequest;
use Kanopi\Firewall\Storage\SharedStorage;
use Kanopi\Firewall\Traits\AddressMatchTrait;
use Kanopi\Firewall\Utility\BlockList;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\Connections;
use Kanopi\Firewall\Utility\DatabaseConsumers;
use Kanopi\Firewall\Utility\PanicSwitch;
use Kanopi\Firewall\Utility\RequestPath;
use Kanopi\Firewall\Utility\TrustedProxies;
use Symfony\Component\HttpFoundation\Request;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDns\SystemResolver;

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
    use AddressMatchTrait;

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
        $findings[] = $this->checkLockdown($global);
        $findings[] = $this->checkPathSource($global);

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

        foreach ($this->checkOfflineVerification($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkReverseDns($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkSchema($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkStorage($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        foreach ($this->checkConnections($config) as $diagnosi) {
            $findings[] = $diagnosi;
        }

        $enumeration = $this->checkEnumeration();

        if ($enumeration instanceof Diagnosis) {
            $findings[] = $enumeration;
        }

        foreach ($this->checkRecordedRequest($config) as $diagnosi) {
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
        // Declared in YAML, it can be read and checked from anywhere -- the
        // one form of this a terminal *can* verify (#397).
        if (!empty($global['trusted_proxies'])) {
            try {
                $declared = TrustedProxies::fromGlobal($global);
            } catch (ConfigurationException $configurationException) {
                return Diagnosis::error(
                    'global.trusted_proxies is refused',
                    $configurationException->getMessage(),
                    'configuration/global.md#trusted-proxies-from-yaml'
                );
            }

            return Diagnosis::ok(
                'Trusted proxies configured in YAML',
                sprintf(
                    '%s. Applied for each evaluation. If the application bootstrap also calls '
                    . 'Request::setTrustedProxies(), its proxies are used instead and this is ignored.',
                    $declared instanceof TrustedProxies ? $declared->describe() : 'none'
                )
            );
        }

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
     * Whether a lockdown would serve anybody at all.
     *
     * `lockdown` is deny-by-default, so an empty `global.lockdown_allow` serves nobody --
     * including whoever flips it. That is the correct reading of the mode and a poor thing
     * to discover by trying it during an incident, which is precisely when it gets reached
     * for (#304).
     *
     * Reported even when the mode is not currently `lockdown`, because the point is to find
     * out *before* relying on it.
     *
     * An entry the firewall cannot read matches nobody, so it is reported by name rather
     * than counted as coverage: a list of one unreadable range is an empty list that says
     * "1 entry" (#407).
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @return Diagnosis
     *   The finding.
     */
    private function checkLockdown(array $global): Diagnosis
    {
        $allowed = $global['lockdown_allow'] ?? null;
        $entries = is_array($allowed)
            ? array_values(array_filter($allowed, static fn(mixed $v): bool => is_string($v) && trim($v) !== ''))
            : [];
        // Both spellings: the `lockdown: true` flag is the one a host using
        // `mode: exception` has to use, and reading only the shorthand reported
        // an active lockdown as "not currently in lockdown".
        $inLockdown = ($global['mode'] ?? null) === 'lockdown' || ($global['lockdown'] ?? false) === true;
        $unusable = array_values(array_filter(
            $entries,
            fn(string $entry): bool => !$this->isValidPattern($entry) && !$this->isValidRange($entry)
        ));

        if ($entries === []) {
            $detail = 'global.lockdown_allow lists nobody, so lockdown would refuse every visitor '
                . 'including you. Add the addresses that must still reach the site.';

            // An error when it is already on, because the site is down; a
            // warning when it is not, because it is a trap set for later.
            return $inLockdown
                ? Diagnosis::error('Lockdown is active and allows nobody', $detail, 'configuration/global.md#lockdown')
                : Diagnosis::warning('Lockdown would allow nobody', $detail, 'configuration/global.md#lockdown');
        }

        if ($unusable !== []) {
            $title = sprintf(
                '%s allowlist has %d entr%s that can never match',
                $inLockdown ? 'Lockdown is ACTIVE and its' : 'Lockdown',
                count($unusable),
                count($unusable) === 1 ? 'y' : 'ies'
            );
            $detail = sprintf(
                '%s %s not an address, a CIDR block or a start-end range, so %s nobody. '
                . 'A lockdown refuses everyone the list does not name.',
                implode(', ', array_map(static fn(string $e): string => '"' . $e . '"', $unusable)),
                count($unusable) === 1 ? 'is' : 'are',
                count($unusable) === 1 ? 'it serves' : 'they serve'
            );

            return $inLockdown
                ? Diagnosis::error($title, $detail, 'configuration/global.md#lockdown')
                : Diagnosis::warning($title, $detail, 'configuration/global.md#lockdown');
        }

        if ($inLockdown) {
            return Diagnosis::warning(
                sprintf('Lockdown is ACTIVE — only %d address range%s is served', count($entries), count($entries) === 1 ? '' : 's'),
                'Everyone else receives a 503. Set global.lockdown to false, or change global.mode off lockdown, '
                . 'to restore normal service.',
                'configuration/global.md#lockdown'
            );
        }

        return Diagnosis::ok(
            sprintf('Lockdown allowlist has %d entr%s', count($entries), count($entries) === 1 ? 'y' : 'ies'),
            'Not currently in lockdown.'
        );
    }

    /**
     * What `path` means for every rule, and whether the setting was understood (#414).
     *
     * An unknown `path_source` falls back to `pathinfo` at runtime rather than refusing to
     * start, so this is the one place it is loud. That matters here more than for most
     * keys: the reason to set it is that path rules were not matching, and a typo in it
     * leaves them not matching while the configuration reads as fixed.
     *
     * @param array<string, mixed> $global
     *   The `global:` block.
     *
     * @return Diagnosis
     *   The finding.
     */
    private function checkPathSource(array $global): Diagnosis
    {
        $source = $global['path_source'] ?? RequestPath::PATHINFO;

        if (!RequestPath::isValidSource($source)) {
            return Diagnosis::error(
                'Path source is not understood, so rules match the front-controller path',
                sprintf(
                    'global.path_source is %s; it takes pathinfo or script_name. Until it is fixed '
                    . 'the firewall uses pathinfo, which is "/" for a file served directly, such as '
                    . "WordPress's wp-login.php.",
                    is_scalar($source) ? '"' . $source . '"' : gettype($source)
                ),
                'configuration/global.md#path-source'
            );
        }

        $basePath = RequestPath::normaliseBasePath($global['base_path'] ?? null);

        if ($basePath === null) {
            return Diagnosis::error(
                'Base path is not usable, so nothing is stripped from the path',
                'global.base_path must be a path such as /blog, with no query or fragment.',
                'configuration/global.md#path-source'
            );
        }

        if ($source === RequestPath::PATHINFO) {
            return Diagnosis::ok(
                'Path rules match the front-controller path (pathinfo)',
                $basePath === ''
                    ? 'A file served directly, such as WordPress\'s wp-login.php, is matched as "/". '
                    . 'Set path_source: script_name if the site serves pages that way.'
                    : 'base_path is set but only applies to path_source: script_name, so it does nothing.'
            );
        }

        return Diagnosis::ok(
            'Path rules match the file the server ran (script_name)',
            $basePath === ''
                ? 'The front controller is /index.php.'
                : sprintf('The front controller is %1$s/index.php, and %1$s is stripped from the front of any other file.', $basePath)
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

        // Said when there are any, and not otherwise: a firewall with no
        // listeners is the default, not something to report (#396).
        $listeners = $firewall->getConfiguredListeners();

        if ($listeners !== []) {
            $findings[] = Diagnosis::ok(
                sprintf('%d decision listener%s registered', count($listeners), count($listeners) === 1 ? '' : 's'),
                implode('; ', $listeners)
            );
        }

        // Reported as OK, deliberately. A rule outside its window is doing
        // exactly what it was configured to do, and a warning for that would
        // fire every night on a correct configuration until nobody read the
        // warnings any more. It still has to be *said*, because a scheduled
        // rule matching nothing looks identical to a broken one (#205).
        foreach ($firewall->getSleepingRules() as $rule) {
            $findings[] = Diagnosis::ok(
                sprintf('Rule %s is asleep right now', $rule['plugin']),
                sprintf(
                    'Configured as a %s rule, awake %s. Until then it matches nothing, which is not '
                    . 'the same as being broken.',
                    $rule['bucket'],
                    $rule['window']
                )
            );
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
                    'Missing %s. Run bin/firewall migrate to add them.',
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

        // A shared block list keeps its real paths one level down, under the
        // backend it falls back to. Checking only the top level found nothing
        // to check and said nothing -- while the local copy, which is the
        // entire reason that arrangement exists, might not be writable (#223).
        // Trimmed, because every documented example writes the class with a
        // leading backslash -- `"\\Kanopi\\Firewall\\Storage\\SharedStorage"` -- and
        // `::class` has none. Comparing them raw matched nothing, which is a
        // check that silently never runs.
        $declaredType = is_string($storage['type'] ?? null) ? ltrim($storage['type'], '\\') : '';

        if ($declaredType === SharedStorage::class) {
            $findings = [Diagnosis::ok(
                'Block list is shared across the fleet',
                sprintf(
                    'Written to %s, with %s kept locally so this node keeps enforcing if the share '
                    . 'cannot be reached.',
                    $this->storageTypeName($settings['shared'] ?? null),
                    $this->storageTypeName($settings['local'] ?? null)
                )
            )];

            $local = is_array($settings['local'] ?? null) ? $settings['local'] : [];
            $localSettings = is_array($local['config'] ?? null) ? $local['config'] : [];

            foreach ($this->checkStoragePaths($localSettings, 'local fallback') as $diagnosi) {
                $findings[] = $diagnosi;
            }

            return $findings;
        }

        return $this->checkStoragePaths($settings, null);
    }

    /**
     * Whether a range search of the block list can currently be trusted (#392).
     *
     * Only a backend that enumerates from an index it can lose has anything to say, so
     * every other backend produces no finding at all rather than an "ok" about a problem
     * it cannot have.
     *
     * @return Diagnosis|null
     *   A warning, or null when there is nothing to report.
     */
    private function checkEnumeration(): ?Diagnosis
    {
        try {
            $gap = (new BlockList($this->configs))->backend()['gap'];
        } catch (\Throwable) {
            // A backend that could not be built is reported by the checks
            // around this one; a second finding would read as a second problem.
            return null;
        }

        if ($gap === null) {
            return null;
        }

        return Diagnosis::warning(
            'Block list searches may be incomplete',
            ucfirst($gap) . '. Blocks are still enforced, and a single address is still found; '
            . '`firewall block --find` and `--list` may miss some.',
            'configuration/storage.md#the-index-is-best-effort'
        );
    }

    /**
     * Whether each declared connection can reach its server (#395).
     *
     * Every declared connection, referenced or not: one declared and never used is
     * harmless, but one declared *to be* used and misspelled where it is referenced is the
     * common mistake, and the report showing it answering is half of finding that out. The
     * target is named without its credentials.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   One finding per connection.
     */
    private function checkConnections(array $config): array
    {
        $connections = Connections::fromConfig($config);
        $findings = [];

        foreach ($connections->names() as $name) {
            $problem = $connections->probe($name);

            $findings[] = $problem === null
                ? Diagnosis::ok(sprintf('Connection %s answers', $name), $connections->describe($name))
                : Diagnosis::error(
                    sprintf('Connection %s could not be reached', $name),
                    sprintf('%s: %s', $connections->describe($name), $problem),
                    'configuration/connections.md'
                );
        }

        return $findings;
    }

    /**
     * What a block record keeps, and whether anything old still holds more (#375).
     *
     * Two different facts, and an operator upgrading needs both. The policy in force now is
     * one config value away from being read wrong. What is *already in the store* is not
     * affected by it at all: redacting on write does nothing about records written before the
     * upgrade, and they are the ones holding session cookies.
     *
     * So this reads the store rather than only the configuration, and says which it found.
     * There is deliberately no command that rewrites them: a record's remaining ban time
     * cannot be read back portably, so scrubbing in place would silently reset every ban to
     * a full term. Clearing is the honest instrument, and it is the operator's call because
     * it un-blocks whoever is currently blocked.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Findings.
     */
    private function checkRecordedRequest(array $config): array
    {
        $storage = is_array($config['storage'] ?? null) ? $config['storage'] : [];
        $settings = is_array($storage['config'] ?? null) ? $storage['config'] : [];
        $recordedRequest = RecordedRequest::fromConfig($settings['record_request'] ?? null);
        $findings = [];

        if ($recordedRequest->keepsEverything()) {
            // Said rather than left as an absence. Somebody who opted back in
            // should be told they did; somebody who typed the key wrong and got
            // this by accident needs to find out here rather than from a ticket.
            $findings[] = Diagnosis::warning(
                'Block records keep every cookie and header the visitor sent',
                "`record_request` opts out of the allowlist, so a blocked visitor's session cookie "
                . 'and any Authorization header are persisted into the block list — which is the '
                . 'artifact that gets pasted into tickets and, with SharedStorage, replicated across '
                . 'the fleet. Narrow it unless you have decided you want that.',
                'configuration/storage.md#what-a-block-record-keeps'
            );
        }

        try {
            $held = $this->recordsHoldingCredentials();
        } catch (\Throwable) {
            // A backend that cannot enumerate, or cannot be reached. Both are
            // already reported by the checks above; saying it twice would read
            // as two problems.
            return $findings;
        }

        if ($held > 0) {
            $findings[] = Diagnosis::warning(
                sprintf('%d existing block record%s still hold%s cookies or headers', $held, $held === 1 ? '' : 's', $held === 1 ? 's' : ''),
                'Written before the allowlist existed, and unaffected by it — redaction happens on '
                . 'write. They expire with their bans; `bin/firewall block --lift` clears them sooner, '
                . 'at the cost of un-blocking whoever is in them.',
                'configuration/storage.md#what-a-block-record-keeps'
            );
        }

        return $findings;
    }

    /**
     * How many stored records still carry a cookie jar or header set.
     *
     * @return int
     *   The count, or 0 when the backend cannot enumerate its own keys.
     */
    private function recordsHoldingCredentials(): int
    {
        // Through `BlockList` rather than building storage here: it is already
        // the thing that turns a configuration into a queryable store, and it
        // answers with an empty list for a backend that cannot enumerate its
        // own keys rather than needing to be asked first.
        $blockList = new BlockList($this->configs);
        $held = 0;

        foreach (['0.0.0.0/0', '::/0'] as $everything) {
            foreach ($blockList->find($everything) as $record) {
                // The payload sits under `value`; the keys beside it are the
                // store's own bookkeeping. Reading `$record['request']` finds
                // nothing and reports a clean store, which is the worst
                // possible answer to this particular question.
                $value = is_array($record['value'] ?? null) ? $record['value'] : [];
                $request = is_array($value['request'] ?? null) ? $value['request'] : [];

                if (($request['cookies'] ?? []) !== [] || ($request['headers'] ?? []) !== []) {
                    $held++;
                }
            }
        }

        return $held;
    }

    /**
     * Rules asking for identity verification on a host where it cannot run (#391).
     *
     * `KANOPI_FIREWALL_SOURCES_OFFLINE` switches verification off unless a rule says
     * otherwise, and a verified allow rule on such a host matches nobody new -- a genuine
     * crawler included. The plugin warns at construction; this puts it in the report an
     * operator reads before a deploy.
     *
     * Answered for *this* process. A host that defines the constant in its web bootstrap
     * and not on the command line will not see this from a terminal, which is the same
     * limit the trusted-proxies check states.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   One warning per affected rule.
     */
    private function checkOfflineVerification(array $config): array
    {
        $plugins = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];
        $findings = [];

        foreach ($plugins as $plugin) {
            $metadata = is_array($plugin) && is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];

            if (($metadata['verify'] ?? null) === null) {
                continue;
            }

            $offline = AbstractPluginBase::verificationOffline($metadata);
            if (!$offline['offline']) {
                continue;
            }

            if ($offline['source'] !== 'constant') {
                continue;
            }

            $findings[] = Diagnosis::warning(
                sprintf('Rule %s asks for verification, and verification is switched off', $this->ruleName($plugin)),
                'KANOPI_FIREWALL_SOURCES_OFFLINE is set, and verification follows it unless the rule '
                . 'says otherwise, so this rule verifies nobody new. Set metadata.verify_offline: false '
                . 'to verify while rule sources stay offline, or true to keep it off deliberately.',
                'plugins/user-agent.md#offline-switches-it-off-unless-the-rule-says-otherwise'
            );
        }

        return $findings;
    }

    /**
     * Where each verifying rule's reverse DNS lookups go (#473).
     *
     * A provider is a third party that receives the reverse-DNS names of visitors'
     * addresses once a site names it, so the report says which one each rule uses -- and
     * which host it sends to -- without anybody reading the YAML.
     *
     * Warns when a DNS-over-HTTPS endpoint names a host and no `address` is pinned: curl
     * then looks the host up through the operating system's resolver first, which has no
     * time limit, and the stall the resolver exists to remove comes back.
     *
     * @param array<string, mixed> $config
     *   The loaded configuration.
     *
     * @return array<int, Diagnosis>
     *   Errors for settings the firewall would refuse, else one finding per verifying rule.
     */
    private function checkReverseDns(array $config): array
    {
        $global = is_array($config['global'] ?? null) ? $config['global'] : [];
        $plugins = is_array($config['plugins'] ?? null) ? $config['plugins'] : [];
        $problems = ReverseDnsSettings::problems($global, $plugins);

        if ($problems !== []) {
            return array_map(
                static fn(string $problem): Diagnosis => Diagnosis::error(
                    'global.reverse_dns cannot be used: ' . $problem,
                    'The firewall refuses to start with it.',
                    'configuration/reverse-dns.md'
                ),
                $problems
            );
        }

        $reverseDnsSettings = ReverseDnsSettings::fromGlobal($global);
        $findings = [];

        foreach ($plugins as $plugin) {
            $metadata = is_array($plugin) && is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];

            if (($metadata['verify'] ?? null) === null) {
                continue;
            }

            $where = $reverseDnsSettings->describeFor($metadata);
            $rule = $this->ruleName($plugin);

            if ($where['provider'] === null && $where['resolver'] === SystemResolver::class) {
                $findings[] = Diagnosis::ok(
                    sprintf("Rule %s verifies with PHP's own lookups", $rule),
                    "SystemResolver, through the operating system's resolver. Its lookups have no time limit; "
                    . "a DNS-over-HTTPS provider's do."
                );
                continue;
            }

            $via = $where['provider'] !== null
                ? sprintf('provider %s', $where['provider'])
                : sprintf('resolver %s', $where['resolver']);

            if ($where['endpoint'] === null) {
                $findings[] = Diagnosis::ok(sprintf('Rule %s verifies through %s', $rule, $via), $where['resolver']);
                continue;
            }

            if ($where['address'] === null && filter_var($where['endpoint'], FILTER_VALIDATE_IP) === false) {
                $findings[] = Diagnosis::warning(
                    sprintf('Rule %s verifies through %s, whose host is looked up without a time limit', $rule, $via),
                    sprintf(
                        'Lookups go to %s, and no address is pinned, so curl first resolves %s through the '
                        . "operating system's resolver. Set the provider's address option to the IP to connect to.",
                        $where['endpoint'],
                        $where['endpoint']
                    ),
                    'configuration/reverse-dns.md'
                );
                continue;
            }

            $findings[] = Diagnosis::ok(
                sprintf('Rule %s verifies through %s', $rule, $via),
                sprintf(
                    "Visitors' reverse-DNS names are sent to %s%s.",
                    $where['endpoint'],
                    $where['address'] !== null ? ', connecting to ' . $where['address'] : ''
                )
            );
        }

        return $findings;
    }

    /**
     * A rule's name for a report: `metadata.name`, else its plugin class's short name.
     *
     * @param mixed $plugin
     *   One `plugins:` entry.
     */
    private function ruleName(mixed $plugin): string
    {
        $metadata = is_array($plugin) && is_array($plugin['metadata'] ?? null) ? $plugin['metadata'] : [];

        if (is_string($metadata['name'] ?? null) && $metadata['name'] !== '') {
            return $metadata['name'];
        }

        $class = is_array($plugin) && is_string($plugin['plugin'] ?? null) ? $plugin['plugin'] : '';
        $short = strrchr($class, '\\');

        return $class === '' ? 'an unnamed rule' : ($short === false ? $class : substr($short, 1));
    }

    /**
     * Name a storage backend for a report, without building it.
     *
     * @param mixed $definition
     *   A `{type, config}` block, or anything else.
     *
     * @return string
     *   The class's short name, or a placeholder.
     */
    private function storageTypeName(mixed $definition): string
    {
        $type = is_array($definition) ? ($definition['type'] ?? null) : null;

        if (!is_string($type) || $type === '') {
            return 'an unnamed backend';
        }

        $short = strrchr($type, '\\');

        return $short === false ? $type : substr($short, 1);
    }

    /**
     * Whether the paths a file-backed store needs are usable.
     *
     * @param array<string, mixed> $settings
     *   A backend's own `config:` block.
     * @param string|null $label
     *   What to call it in the finding, when it is not the only store.
     *
     * @return array<int, Diagnosis>
     *   Findings, empty for a backend that uses no paths.
     */
    private function checkStoragePaths(array $settings, ?string $label): array
    {
        $findings = [];
        $suffix = $label === null ? '' : sprintf(' [%s]', $label);

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
                    sprintf('Storage directory for %s does not exist%s', $key, $suffix),
                    $directory,
                    'configuration/storage.md'
                );

                continue;
            }

            if (!is_writable($directory) || (is_file($path) && !is_writable($path))) {
                $findings[] = Diagnosis::error(
                    sprintf('Storage path for %s is not writable%s', $key, $suffix),
                    $path,
                    'configuration/storage.md'
                );

                continue;
            }

            $findings[] = Diagnosis::ok(sprintf('Storage path writable (%s)%s', $key, $suffix), $path);
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
        $unverified = [];
        $verified = 0;
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

                // Remote only. A local file is whatever the pipeline that put
                // it there put there, and reporting it as unverified says
                // something about that pipeline rather than about this config.
                if ($definition->isRemote()) {
                    if ($definition->isVerified()) {
                        $verified++;
                    } else {
                        $unverified[] = $definition->name;
                    }
                }

                if ($meta === []) {
                    $findings[] = Diagnosis::warning(
                        'Rule source has never been fetched',
                        $url . ' — run bin/firewall sources, or the first request that needs it fetches it inline.',
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

        if ($verified > 0) {
            $findings[] = Diagnosis::ok(sprintf(
                '%d rule source%s verified against a published checksum or signature',
                $verified,
                $verified === 1 ? '' : 's'
            ));
        }

        if ($unverified !== []) {
            // One line for all of them, not one per source. Most published
            // lists in this ecosystem ship no sidecar at all, so per-source
            // warnings would be a wall of noise about something the operator
            // frequently cannot fix -- and a wall of noise is read as
            // background rather than as a finding (#365).
            $findings[] = Diagnosis::warning(
                sprintf('%d remote rule source%s fetched without verification', count($unverified), count($unverified) === 1 ? '' : 's'),
                sprintf(
                    '%s — HTTPS authenticates the host and protects the transport; it says nothing about a '
                    . 'repository that was compromised or a CDN object that was replaced. Add `checksum: sha256` '
                    . 'where the publisher ships a sidecar, or `signature:` with a pinned key where they sign.',
                    implode(', ', $unverified)
                ),
                'configuration/sources.md#verifying-what-you-fetched'
            );
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
