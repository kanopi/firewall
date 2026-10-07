<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Challenge\ChallengeProviderAwareInterface;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Source\SourceAuth;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Utility\Config;
use Kanopi\Firewall\Utility\NestedArray;
use Kanopi\Firewall\Utility\RuleDiagnostics;
use Kanopi\Firewall\Utility\Schedule;
use Kanopi\Firewall\Utility\Path;
use Kanopi\Firewall\Utility\ReverseDnsVerifier;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsResolverInterface;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use Kanopi\Firewall\Utility\ReverseDns\UnusableResolver;
use Kanopi\Firewall\Cache\CachePoolException;
use Kanopi\Firewall\Cache\CachePoolFactory;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Plugin used for creating a plugin.
 */
abstract class AbstractPluginBase implements PluginInterface, ObserveModeInterface, IdentityVerificationInterface, ChallengeProviderAwareInterface, ScheduledRuleInterface
{
    use LoggingTrait;

    /**
     * List of all the files being loaded.
     */
    protected array $files = [];

    /**
     * Which declared source contributed each entry, by config index.
     *
     * Only populated for entries that came from `metadata.sources`. Inline
     * `config:` entries and anything loaded through the legacy
     * `metadata.config` are absent, so a lookup miss means "local".
     *
     * @var array<int, string>
     */
    protected array $sourceProvenance = [];

    /**
     * Lazily built verifier, so a rule that never matches never builds one.
     */
    protected ?ReverseDnsVerifier $reverseDnsVerifier = null;

    /**
     * When this rule is awake, or NULL for a rule that always is.
     */
    protected ?Schedule $schedule = null;

    /**
     * {@inheritdoc}
     *
     * Reads `metadata.verify`. Absent means no verification, which is every existing
     * configuration.
     */
    public function passesIdentityVerification(Request $request): bool
    {
        $verify = $this->metadata['verify'] ?? null;

        if ($verify === null) {
            return true;
        }

        if (!is_string($verify) || strtolower(trim($verify)) !== 'reverse-dns') {
            $this->getLogger()->warning('Plugin verify method is not recognised - the rule will not match', [
                'plugin' => $this->getName(),
                'verify' => is_scalar($verify) ? (string) $verify : gettype($verify),
                'detail' => 'The only supported value is "reverse-dns". Remove the key to skip verification.',
            ]);

            // Not "match anyway". An operator who asked for verification and
            // mistyped it should not silently get an unverified allow rule.
            return false;
        }

        $suffixes = $this->metadata['verify_suffixes'] ?? [];
        $suffixes = is_array($suffixes) ? array_values(array_filter($suffixes, is_string(...))) : [];

        if ($suffixes === []) {
            $this->getLogger()->warning('Plugin verify is set with no verify_suffixes - the rule will not match', [
                'plugin' => $this->getName(),
                'detail' => 'Without a domain list any host with a PTR record would verify, '
                    . 'which is not verification. List the crawler domains you accept.',
            ]);

            return false;
        }

        $ip = $request->getClientIp();

        if (!is_string($ip) || $ip === '') {
            return false;
        }

        return $this->reverseDnsVerifier()->verify($ip, $suffixes);
    }

    /**
     * The verifier, built from this plugin's cache configuration.
     *
     * @return ReverseDnsVerifier
     *   The verifier.
     */
    protected function reverseDnsVerifier(): ReverseDnsVerifier
    {
        if (!$this->reverseDnsVerifier instanceof ReverseDnsVerifier) {
            $ttl = $this->metadata['verify_ttl'] ?? 3600;
            $negativeTtl = $this->metadata['verify_negative_ttl'] ?? 86400;
            $claimWait = $this->metadata['verify_claim_wait_ms'] ?? 0;

            // `global.reverse_dns`, which `Firewall::create()` validated (#473). NULL
            // when nothing is configured, so the verifier makes PHP's own lookups, as
            // every release before this one did.
            $reverseDnsSettings = ReverseDnsSettings::current();
            $resolver = $this->reverseDnsResolver($reverseDnsSettings);
            $threshold = $this->metadata['verify_slow_threshold_ms'] ?? $reverseDnsSettings->slowThresholdFor($this->metadata);

            $this->reverseDnsVerifier = new ReverseDnsVerifier(
                $this->identityCachePool(),
                is_numeric($ttl) ? (int) $ttl : 3600,
                is_numeric($negativeTtl) ? (int) $negativeTtl : 86400,
                // `metadata.verify_offline` when it is set, and otherwise the
                // switch that keeps rule sources and remote configs off the
                // request path (#228). They were one switch until #391, which
                // left verified crawler rules unreachable on any host that
                // keeps rule sources offline -- as drupal/basic_firewall does by
                // default.
                self::verificationOffline($this->metadata)['offline'],
                is_numeric($threshold) ? (float) $threshold : 250.0,
                300,
                // Off unless asked for. It trades latency for a verdict on a
                // cold-cache collision, and which of those matters more is the
                // operator's call rather than ours (#261).
                is_numeric($claimWait) ? max(0, (int) $claimWait) : 0,
                $resolver,
                60,
                // Verdicts and the breaker per resolver, so a switch starts afresh and one
                // slow resolver does not switch off rules that use another (#473).
                $reverseDnsSettings->scopeFor($this->metadata)
            );
        }

        return $this->reverseDnsVerifier;
    }

    /**
     * The resolver this rule's verification uses, or NULL for PHP's own lookups.
     *
     * A provider or resolver that cannot be built has already stopped the firewall
     * starting. Reaching here with one means the rule was built some other way -- a test,
     * or a host constructing plugins itself -- and the answer is the one an unusable
     * verification always gets: no verdict, so the allow rule does not match. A resolver
     * that silently fell back to PHP's lookups would send nothing where the site asked,
     * and mean the site was not told.
     *
     * @param ReverseDnsSettings $reverseDnsSettings
     *   The settings.
     */
    private function reverseDnsResolver(ReverseDnsSettings $reverseDnsSettings): ?ReverseDnsResolverInterface
    {
        try {
            return $reverseDnsSettings->resolverFor($this->metadata);
        } catch (ConfigurationException $configurationException) {
            $this->getLogger()->error('Reverse DNS resolver could not be built - the rule will not match', [
                'plugin' => $this->getName(),
                'error' => $configurationException->getMessage(),
            ]);

            return new UnusableResolver($configurationException->getMessage());
        }
    }

    /**
     * The pool for verification verdicts.
     *
     * `metadata.verify_cache` takes the same shapes as every other cache setting -- a
     * pool, a class name with `args`, or a DSN -- and a filesystem pool when it names
     * none. Before #394 it took only an already-built pool, so YAML could not choose a
     * backend here at all.
     *
     * Its own namespace rather than sharing whatever a plugin uses for other things, so
     * clearing one cache cannot quietly widen an allow rule by discarding verdicts.
     *
     * @return CacheItemPoolInterface|null
     *   The pool, or NULL when one cannot be built.
     */
    protected function identityCachePool(): ?CacheItemPoolInterface
    {
        $configured = $this->metadata['verify_cache'] ?? null;

        try {
            $pool = CachePoolFactory::create($configured, 'kanopi_firewall_rdns', 3600);
        } catch (CachePoolException $cachePoolException) {
            // Falls back to the file cache rather than to none. Without a cache
            // every request pays a DNS round trip; a local cache is still far
            // better than that, and it is what an unconfigured plugin uses.
            $this->getLogger()->warning('Reverse DNS cache could not be built from verify_cache - using the file cache', [
                'plugin' => $this->getName(),
                'adaptor' => CachePoolFactory::describe(is_array($configured) ? ($configured['adaptor'] ?? null) : $configured),
                'error' => $cachePoolException->getMessage(),
            ]);

            $pool = null;
        }

        if ($pool instanceof CacheItemPoolInterface) {
            return $pool;
        }

        try {
            return new FilesystemAdapter(
                'kanopi_firewall_rdns',
                3600,
                defined('KANOPI_FIREWALL_CACHE_DIR')
                    ? (string) constant('KANOPI_FIREWALL_CACHE_DIR')
                    : sys_get_temp_dir() . '/kanopi-firewall-rdns'
            );
            // @codeCoverageIgnoreStart
            // FilesystemAdapter defers its directory work to first use, so its
            // constructor does not throw for a path that cannot be created --
            // pointing it at a path under an existing file proves as much.
            // Kept because the contract permits a throw and a different pool
            // implementation may take it; excluded because nothing can trigger
            // it here, and a test that cannot fail is worse than an annotation
            // that says why.
        } catch (\Throwable $throwable) {
            // No cache means a DNS round trip per request, which is slow but
            // still correct. Losing the rule entirely would be worse.
            $this->getLogger()->warning('Reverse DNS cache could not be created - verifying without a cache', [
                'plugin' => $this->getName(),
                'error' => $throwable->getMessage(),
            ]);

            return null;
        }

        // @codeCoverageIgnoreEnd
    }

    /**
     * {@inheritdoc}
     *
     * Reads `metadata.mode`. Absent -- which is every existing configuration -- means
     * enforce, so nothing changes for a rule that declares nothing.
     */
    /**
     * The attribute name a `response: mark` rule annotates the request with.
     *
     * Defaults to the rule's own name, so `metadata.name: suspicious-agent` becomes
     * `firewall.mark.suspicious-agent` without anything else being configured. A rule that
     * wants several rules to raise one shared signal names it explicitly.
     *
     * @return string
     *   The attribute suffix.
     */
    public function getMarkName(): string
    {
        $configured = $this->metadata['mark_as'] ?? null;

        if (is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        return $this->getName();
    }

    /**
     * An optional header to set on the request alongside the attribute.
     *
     * For a host that reads headers rather than HttpFoundation attributes. Empty by
     * default: a firewall that silently adds headers to every marked request is a firewall
     * that surprises whatever reads them next.
     *
     * @return string
     *   The header name, or an empty string.
     */
    public function getMarkHeader(): string
    {
        $header = $this->metadata['mark_header'] ?? null;

        return is_string($header) ? trim($header) : '';
    }

    /**
     * Whether the rule explicitly opted *in* to recording.
     *
     * Separate from `recordsOffenses()`, which answers the opposite question with the
     * opposite default. A block records unless told not to; a redirect records only when
     * told to. Both are "what would surprise an operator least", and they differ because
     * one is a ban and the other is a signpost.
     *
     * @return bool
     *   TRUE only when `metadata.record` is the boolean TRUE.
     */
    public function recordsExplicitly(): bool
    {
        return ($this->metadata['record'] ?? null) === true;
    }

    /**
     * Where a `response: redirect` rule sends the visitor.
     *
     * Read from the rule's own configuration and never from the request, which is what
     * keeps it from becoming an open redirect. A rule with no destination cannot act; the
     * firewall treats that as a misconfiguration rather than guessing at one.
     *
     * @return string
     *   The destination, or an empty string when none is configured.
     */
    public function getRedirectLocation(): string
    {
        $location = $this->metadata['redirect_to'] ?? null;

        return is_string($location) ? trim($location) : '';
    }

    /**
     * Which redirect status to send.
     *
     * 302 by default: a rule's verdict can change with the next configuration edit, and a
     * 301 is cached by browsers and intermediaries more or less forever. Somebody caught by
     * a rule that is later tuned should not keep being sent to the notice page long after
     * the rule stopped matching.
     *
     * @return int
     *   301, 302, 307 or 308. Anything else falls back to 302.
     */
    public function getRedirectStatus(): int
    {
        $status = $this->metadata['redirect_status'] ?? null;

        return in_array($status, [301, 302, 307, 308], true) ? $status : 302;
    }

    /**
     * Whether a block by this rule is written to the durable block list.
     *
     * `metadata.record: false` refuses the request and records nothing, which is what a
     * deliberate temporary refusal of everybody needs: a lockdown that records every
     * visitor leaves a block list full of customers once it is lifted, each on an
     * escalating ban nobody asked for (#203, #304).
     *
     * Defaults to TRUE, and only an explicit boolean turns it off -- `record: "false"` is a
     * string and does not, the same way every other boolean in this configuration behaves.
     *
     * @return bool
     *   TRUE when a block by this rule is recorded.
     */
    public function recordsOffenses(): bool
    {
        $configured = $this->metadata['record'] ?? null;

        return !is_bool($configured) || $configured;
    }

    /**
     * {@inheritdoc}
     */
    public function isObserveMode(): bool
    {
        $mode = $this->metadata['mode'] ?? null;

        return is_string($mode) && strtolower(trim($mode)) === 'log';
    }

    /**
     * Whether this rule's identity verification makes network calls, and who decided.
     *
     * `metadata.verify_offline` wins when it is set. Otherwise it follows
     * `KANOPI_FIREWALL_SOURCES_OFFLINE`, which is what it always did, so no host changes
     * behaviour on upgrade (#391).
     *
     * Static and public so that `firewall-doctor` answers the question from the same
     * place the rule does, rather than from a copy of this logic.
     *
     * @param array<string, mixed> $metadata
     *   A rule's `metadata:`.
     *
     * @return array{offline: bool, source: string}
     *   `source` is `metadata`, `constant`, or `default` when neither is set.
     */
    public static function verificationOffline(array $metadata): array
    {
        $configured = $metadata['verify_offline'] ?? null;

        if ($configured !== null) {
            $parsed = is_bool($configured) ? $configured : filter_var($configured, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

            if (is_bool($parsed)) {
                return ['offline' => $parsed, 'source' => 'metadata'];
            }
        }

        if (defined('KANOPI_FIREWALL_SOURCES_OFFLINE')) {
            return ['offline' => (bool) constant('KANOPI_FIREWALL_SOURCES_OFFLINE'), 'source' => 'constant'];
        }

        return ['offline' => false, 'source' => 'default'];
    }

    /**
     * Say so when a rule's verification has been switched off by another feature's switch.
     *
     * Offline, verification never resolves, and nothing else writes the verdict cache --
     * so unless a shared `verify_cache` holds verdicts another node wrote, a rule that
     * asks for verification matches nobody, a genuine crawler included. That is the
     * right direction to fail for an allow rule, and it was silent: a `debug` line per
     * request was the only trace (#391).
     *
     * Only when the constant decided. An explicit `verify_offline: true` is the operator
     * choosing, and saying so on every request would be noise about a decision.
     *
     * Once per construction, because it is a configuration problem.
     */
    protected function reportOfflineVerification(): void
    {
        if (($this->metadata['verify'] ?? null) === null) {
            return;
        }

        $offline = self::verificationOffline($this->metadata);

        if (!$offline['offline'] || $offline['source'] !== 'constant') {
            return;
        }

        $this->getLogger()->warning('Plugin verify is switched off by KANOPI_FIREWALL_SOURCES_OFFLINE - the rule will not verify anyone new', [
            'plugin' => $this->getName(),
            'detail' => 'That constant keeps rule sources off the request path, and verification follows it '
                . 'unless told otherwise. Set metadata.verify_offline: false to verify while sources stay '
                . 'offline, or verify_offline: true to keep it off deliberately and stop this warning. '
                . 'Offline, only verdicts already in a shared verify_cache are honoured.',
        ]);
    }

    /**
     * Tell the operator when `metadata.mode` says something unrecognised.
     *
     * A typo here fails in the dangerous direction: `mode: lgo` or `mode: observe` is not
     * observe mode, so a rule the operator believed was watching quietly is enforcing on
     * live traffic. Silence would be the worst possible answer.
     *
     * Once per construction, because it is a configuration problem.
     */
    protected function reportUnrecognisedMode(): void
    {
        $mode = $this->metadata['mode'] ?? null;

        if ($mode === null) {
            return;
        }

        if (is_string($mode) && in_array(strtolower(trim($mode)), ['log', 'block', 'enforce'], true)) {
            return;
        }

        $this->getLogger()->warning('Plugin mode is not recognised - the rule will enforce', [
            'plugin' => $this->getName(),
            'mode' => is_scalar($mode) ? (string) $mode : gettype($mode),
            'detail' => 'Use "log" to match without acting. Omit the key, or use "block", to enforce.',
        ]);
    }

    /**
     * Return logging context for the plugin.
     *
     * @return array
     *   Return additional logging context.
     */
    protected function getLoggingContext(): array
    {
        return [
            'plugin_name' => $this->getName(),
            // `static::class`, not `self::class`. Pre-fix this resolved here,
            // in the abstract, so every plugin reported its type as
            // `AbstractPluginBase` on any line it logged itself. That was
            // survivable while `plugin_name` identified the rule; it is not
            // once `metadata.name` makes the name arbitrary, because the class
            // is then the only stable identifier a log reader has left.
            'plugin_type' => static::class,
        ];
    }

    /**
     * {@inheritdoc}
     *
     * Prefers `metadata.name` over what the plugin class calls itself.
     *
     * `defaultName()` is hardcoded per class, so a configuration with four
     * `IpAddress` entries -- an allow list for the office, one for a monitoring
     * vendor, a block list for known-bad ranges, a challenge list for cloud
     * egress -- logged all four as `IP Address`. Nothing reading those lines
     * back could tell which rule fired, which is the whole question a firewall
     * log is asked.
     *
     * Declaring nothing keeps the name the plugin has always had, so no
     * existing configuration changes what it logs.
     */
    public function getName(): string
    {
        $name = $this->metadata['name'] ?? null;

        if (!is_string($name)) {
            return $this->defaultName();
        }

        $name = trim($name);

        // An empty or whitespace-only `name:` is a half-written key, not an
        // assertion that this rule has no name. Falling back beats logging ''.
        return $name === '' ? $this->defaultName() : $name;
    }

    /**
     * Return the name this plugin class carries when none is configured.
     *
     * Concrete rather than abstract on purpose: a plugin outside this package
     * that implements `getName()` itself -- the shape every plugin here had
     * before `metadata.name` existed, and the one the custom-plugin guide
     * documented -- keeps working untouched. Adding an abstract method here
     * would have made every such class fatally incomplete on upgrade.
     *
     * @return string
     *   The plugin's short class name, unless the plugin says otherwise.
     */
    protected function defaultName(): string
    {
        $parts = explode('\\', static::class);

        return end($parts);
    }

    /**
     * Constructs a new plugin.
     *
     * @param array<int|string, mixed> $metadata
     *   Metadata for the plugin.
     * @param array<int|string, mixed> $config
     *   Configuration for the plugin.
     */
    public function __construct(protected array $metadata = [], protected array $config = [])
    {
        $entries = $this->loadDeclaredSources();

        // Load the extra config files for each plugin.
        if (isset($metadata['config'])) {
            $files = $metadata['config'];
            if (!is_array($files)) {
                if (is_string($files) && !Path::looksLikeUrl($files)) {
                    // Keep the path as written when realpath() fails. It used
                    // to become `false`, which Config::load() skips without a
                    // word; as a string it reaches Config::loadFile(), which
                    // records why it could not be read (#78).
                    $files = [@realpath($files) ?: $files];
                } elseif (is_string($files) && Path::looksLikeUrl($files)) {
                    $files = [$files];
                } else {
                    $files = [];
                }
            }


            $files[] = $config;
            $files = array_filter($files);

            foreach ($files as &$file) {
                if (is_string($file) && !Path::looksLikeUrl($file)) {
                    $file = realpath($file) ?: $file;
                }
            }

            unset($file);

            $this->files = $files;

            // A plugin's own config files fail open exactly like the top-level
            // ones do: an unreadable or malformed file leaves the plugin with
            // an empty rule list, which for a block plugin means it matches
            // nothing. Report what did not load — the logger is already
            // configured by the time plugins are constructed, so unlike the
            // bootstrap load this can be logged directly (#78).
            Config::clearLoadErrors();
            $this->config = Config::load($files);

            foreach (Config::getLoadErrors() as $error) {
                $this->getLogger()->error('Plugin config file failed to load — its rules are NOT active', [
                    'plugin' => $this->getName(),
                    'file' => $error['file'],
                    'reason' => $error['message'],
                ]);
            }

            foreach (Config::getLoadWarnings() as $warning) {
                $this->getLogger()->warning('Plugin config file loaded in a degraded state', [
                    'plugin' => $this->getName(),
                    'file' => $warning['file'],
                    'reason' => $warning['message'],
                ]);
            }

            $this->warnLegacyListConfig();

            $this->getLogger()->debug('Plugin initialized with config files', [
                'plugin' => $this->getName(),
                'config_files' => array_filter($files, is_string(...)),
                'metadata' => $this->redactedMetadata(),
            ]);
        } else {
            $this->getLogger()->debug('Plugin initialized', [
                'plugin' => $this->getName(),
                'metadata' => $this->redactedMetadata(),
                'config' => $this->config,
            ]);
        }

        $this->config = $this->mergeSourceEntries($entries, $this->config);
        $this->reportUnusableRules();
        $this->reportUnrecognisedMode();
        $this->reportOfflineVerification();

        // Last, and allowed to throw. A schedule nobody can read is a rule
        // nobody can reason about, so it takes the rule out rather than
        // guessing which way the operator meant it (#205). Everything above
        // has already been logged by the time it does.
        $this->schedule = Schedule::fromMetadata($this->metadata['active'] ?? null);
    }

    /**
     * Whether this rule is inside its active window right now.
     *
     * Asked by `PluginManager` before evaluation rather than inside it, so a
     * sleeping rule costs one comparison and takes no side effect with it.
     *
     * @return bool
     *   TRUE when the rule should be evaluated.
     */
    public function isActiveNow(): bool
    {
        if (!$this->schedule instanceof Schedule) {
            return true;
        }

        return $this->schedule->isActiveAt(new \DateTimeImmutable('now'));
    }

    /**
     * The schedule this rule keeps, if it keeps one.
     *
     * @return Schedule|null
     *   NULL for a rule that runs at all times.
     */
    public function getSchedule(): ?Schedule
    {
        return $this->schedule;
    }

    /**
     * Variable roots this plugin's rules may address.
     *
     * Returning a non-empty list opts the plugin into rule checking at
     * construction: a rule naming something outside it matches nothing, and
     * saying so is the difference between a five-second fix and an afternoon.
     *
     * The default is empty, which disables checking. That is correct for
     * plugins whose `config` is not a rule list at all — `IpAddress` takes bare
     * addresses, `VulnerabilityScore` a nested scoring tree — where every entry
     * would otherwise be reported as an unknown variable.
     *
     * @return array<int, string>
     *   Known variable roots, or an empty array to skip checking.
     */
    protected function knownRuleVariables(): array
    {
        return [];
    }

    /**
     * Report rules that cannot match anything, and repair the ones that can be.
     *
     * Runs once per plugin instance at construction rather than per request:
     * this is a configuration problem, and a configuration problem should be
     * reported when the configuration is read.
     */
    protected function reportUnusableRules(): void
    {
        $known = $this->knownRuleVariables();

        if ($known === [] || $this->config === [] || !array_is_list($this->config)) {
            return;
        }

        $result = RuleDiagnostics::inspect($this->config, $known);
        $this->config = $result['rules'];

        foreach ($result['issues'] as $issue) {
            $this->getLogger()->warning('Firewall rule will not match anything', [
                'plugin' => $this->getName(),
                'rule' => $issue['rule'],
                'reason' => $issue['reason'],
            ]);
        }
    }

    /**
     * Metadata with source credentials removed, for logging.
     *
     * The debug lines below dump the whole metadata array, which for a source
     * behind authentication would put a bearer token or password straight into
     * the log. Nothing else in metadata is secret, so only `sources.*.upstream`
     * is scrubbed — and it is replaced with the redacted URL so the line still
     * says which list it is talking about.
     *
     * @return array<int|string, mixed>
     *   Metadata safe to log.
     */
    protected function redactedMetadata(): array
    {
        $metadata = $this->metadata;

        if (!isset($metadata['sources']) || !is_array($metadata['sources'])) {
            return $metadata;
        }

        foreach ($metadata['sources'] as $index => $source) {
            if (is_string($source)) {
                $metadata['sources'][$index] = SourceAuth::redactUrl($source);
                continue;
            }

            if (!is_array($source)) {
                continue;
            }

            if (!array_key_exists('upstream', $source)) {
                continue;
            }

            $upstream = $source['upstream'];

            if (is_string($upstream)) {
                $metadata['sources'][$index]['upstream'] = SourceAuth::redactUrl($upstream);
                continue;
            }

            if (is_array($upstream)) {
                unset($metadata['sources'][$index]['upstream']['auth']);
                unset($metadata['sources'][$index]['upstream']['headers']);

                if (is_string($upstream['url'] ?? null)) {
                    $metadata['sources'][$index]['upstream']['url'] = SourceAuth::redactUrl($upstream['url']);
                }
            }
        }

        return $metadata;
    }

    /**
     * Load every source declared under `metadata.sources`.
     *
     * Failures are governed by each source's own `on_error` and `required`
     * settings; a source marked required rethrows and takes the bootstrap with
     * it, which is what an allow list wants and a block list does not.
     *
     * @return array<int, mixed>
     *   Merged entries in declaration order, empty when nothing is declared.
     */
    protected function loadDeclaredSources(): array
    {
        $declared = $this->metadata['sources'] ?? null;

        if (!is_array($declared) || $declared === []) {
            return [];
        }

        $sourceManager = $this->sourceManager();
        $entries = $sourceManager->load($declared);

        $this->sourceProvenance = $sourceManager->provenance();

        foreach ($sourceManager->errors() as $error) {
            $this->getLogger()->warning('Plugin source did not contribute its entries', [
                'plugin' => $this->getName(),
                'source' => $error['source'],
                'reason' => $error['message'],
            ]);
        }

        return $entries;
    }

    /**
     * Combine source entries with whatever the plugin already had.
     *
     * `NestedArray::mergeDeepArray()` renumbers integer keys, so list entries
     * from sources append ahead of local ones while a map-shaped document —
     * the nested `scoring` and `risk_levels` trees VulnerabilityScore loads —
     * still merges by key. Local config lands last either way, so a site can
     * always add to a shared list without editing it.
     *
     * @param array<int, mixed> $entries
     *   Entries produced by declared sources.
     * @param array<array-key, mixed> $config
     *   Configuration assembled from files and inline rules.
     *
     * @return array<array-key, mixed>
     *   The merged configuration.
     */
    protected function mergeSourceEntries(array $entries, array $config): array
    {
        if ($entries === []) {
            return $config;
        }

        return NestedArray::mergeDeepArray([$entries, $config]);
    }

    /**
     * Note when `metadata.config` is doing a job `metadata.sources` now does.
     *
     * The key is only deprecated for rule *lists*, which sources handle with
     * declared formats and failure policies. It stays the mechanism for merging
     * nested configuration documents, so the notice is limited to the case that
     * actually has a replacement rather than firing on every use.
     */
    protected function warnLegacyListConfig(): void
    {
        if (isset($this->metadata['sources']) || $this->config === [] || !array_is_list($this->config)) {
            return;
        }

        $this->getLogger()->notice(
            'metadata.config is deprecated for rule lists; declare metadata.sources instead, '
            . 'which adds format handling, filtering, and per-source failure policy',
            [
                'plugin' => $this->getName(),
                'files' => array_values(array_filter($this->files, is_string(...))),
            ]
        );
    }

    /**
     * The source manager used to resolve `metadata.sources`.
     *
     * Overridable so tests can supply a manager backed by a temporary cache.
     *
     * @return SourceManager
     *   The manager.
     */
    protected function sourceManager(): SourceManager
    {
        return new SourceManager();
    }

    /**
     * Which source contributed the entry at a config index.
     *
     * @param int $index
     *   Index into the plugin's merged config.
     *
     * @return string|null
     *   The source name, or NULL when the entry is local.
     */
    public function entrySource(int $index): ?string
    {
        return $this->sourceProvenance[$index] ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function getStatusCode(?Request $request = null): int
    {
        return intval($this->metadata['status_code'] ?? 400);
    }

    /**
     * {@inheritdoc}
     */
    public function getExpirationTime(?Request $request = null): int
    {
        return intval($this->metadata['default_expiration_time'] ?? 0);
    }

    /**
     * How long a `response: tarpit` rule asks to hold a request for.
     *
     * Read from `metadata.tarpit_seconds`. What comes back is a request rather
     * than an instruction -- `tarpit.max_seconds` is the ceiling, because a
     * rule asking for five minutes is asking for a php-fpm worker held for five
     * minutes and whoever wrote it may not have meant that (#329).
     *
     * @return int
     *   Seconds. Zero means none was named, which `TarpitGate` reads as the
     *   minimum rather than as no delay: a tarpit rule that does not tarpit is
     *   a rule doing nothing at all.
     */
    public function getTarpitSeconds(): int
    {
        return max(0, intval($this->metadata['tarpit_seconds'] ?? 0));
    }

    /**
     * The message this rule's blocks are refused with, if it sets one (#452).
     *
     * Read from `metadata.banning_message`, in place of `global.banning_message` -- and,
     * on a block page, used as its message when the page sets none. Only consulted for
     * blocks this rule causes.
     *
     * @return string|null
     *   The template, or NULL to use the global one.
     */
    public function getBanningMessage(): ?string
    {
        $message = $this->metadata['banning_message'] ?? null;

        return is_string($message) && trim($message) !== '' ? $message : null;
    }

    /**
     * This rule's block page, as configured (#452).
     *
     * `metadata.block_page`: `true`, or a map merged over `global.block_page` for blocks
     * this rule causes. Validated when the firewall is built, and read back through
     * `BlockPage::settings()`.
     *
     * @return mixed
     *   The raw value; NULL when the rule sets none.
     */
    public function getBlockPage(): mixed
    {
        return $this->metadata['block_page'] ?? null;
    }

    /**
     * {@inheritdoc}
     *
     * Read from `metadata.challenge_provider`, alongside the other
     * per-entry knobs. Only consulted for `response: challenge` entries —
     * setting it on a block or allow plugin is inert rather than an error,
     * since the same plugin class is often used for all three.
     */
    public function getChallengeProviderName(): ?string
    {
        $provider = $this->metadata['challenge_provider'] ?? null;

        if (!is_string($provider)) {
            return null;
        }

        $provider = trim($provider);

        return $provider === '' ? null : $provider;
    }
}
