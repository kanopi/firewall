<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use DeviceDetector\Cache\CacheInterface;
use DeviceDetector\Cache\PSR6Bridge;
use DeviceDetector\ClientHints;
use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\AbstractDeviceParser;
use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Utility\SelectiveDeviceDetector;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate a User Agent.
 */
class UserAgent extends AbstractPluginBase
{
    use EvaluateTrait;

    /**
     * Device Detector for the current request.
     */
    protected DeviceDetector $deviceDetector;

    /**
     * Regex-corpus cache handed to every DeviceDetector instance (#107).
     *
     * NULL when caching is switched off, or when the configured adaptor could
     * not be built — in which case the plugin still works, just slowly.
     */
    protected ?CacheInterface $cache = null;

    /**
     * Whether the cache has been resolved yet.
     *
     * Resolution is deferred to the first evaluation rather than done in the
     * constructor: plugins are instantiated lazily by `PluginManager`, but a
     * config can still declare a plugin that never runs, and building a cache
     * adaptor is not free — it creates directories.
     */
    private bool $cacheResolved = false;

    /**
     * Deepest parse phase the configured rules need, resolved once (#108).
     */
    private ?string $requiredPhase = null;

    /**
     * Is this request automated, by any source we have (#109)?
     *
     * `bot:true` is device-detector's curated bot database, and it does not
     * classify a good deal of the tooling a firewall exists to stop:
     *
     *   missed:  sqlmap, nikto, curl, python-requests, Go-http-client
     *   caught:  masscan, nmap, zgrab, wpscan, nuclei, dirbuster,
     *            googlebot, bingbot, ahrefs, gptbot
     *
     * `automated:true` is the union of that database and a broader crawler
     * list which does catch them.
     *
     * WHY A SECOND VARIABLE RATHER THAN WIDENING `bot`:
     *
     * The wider list deliberately counts generic HTTP client libraries as
     * automated. Redefining `bot:true` to include them would start blocking a
     * partner integration or mobile app built on python-requests, on a rule
     * the operator wrote long ago and has not touched — a behaviour change to
     * a blocking rule, arriving in a minor release. As a distinct variable it
     * is one line to opt into, and one line to leave alone.
     *
     * It is also why this is not a `metadata` setting: the plugin's vocabulary
     * is its rules, and a rule reads better than a config knob that silently
     * changes what an existing rule means.
     *
     * @return bool
     *   Whether any source considers the agent automated.
     */
    protected function isAutomated(): bool
    {
        if ($this->deviceDetector->isBot()) {
            return true;
        }

        return $this->deviceDetector instanceof SelectiveDeviceDetector
            && $this->deviceDetector->isCrawler();
    }

    /**
     * Which parse phase produces each rule variable.
     *
     * Mirrors the switch in `getValue()`. Kept beside it deliberately: if a
     * variable is added there without a line here it resolves to the deepest
     * phase, so the new variable works and merely forgoes the optimisation.
     */
    private const VARIABLE_PHASES = [
        'bot' => SelectiveDeviceDetector::PHASE_BOT,
        'automated' => SelectiveDeviceDetector::PHASE_BOT,
        'os' => SelectiveDeviceDetector::PHASE_OS,
        'client' => SelectiveDeviceDetector::PHASE_CLIENT,
        'device' => SelectiveDeviceDetector::PHASE_DEVICE,
        'brand' => SelectiveDeviceDetector::PHASE_DEVICE,
        'model' => SelectiveDeviceDetector::PHASE_DEVICE,
    ];

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'User Agent';
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return 'Evaluate the User Agent';
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        $userAgent = $request->headers->get('User-Agent', '');
        $this->deviceDetector = $this->detectDevice($userAgent);

        $this->getLogger()->debug('User Agent evaluation started', $this->getContext($request, [
            'is_bot' => $this->deviceDetector->isBot(),
            'device_type' => $this->deviceDetector->getDeviceName(),
            'client' => $this->deviceDetector->getClient(),
            'os' => $this->deviceDetector->getOs(),
        ]));

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('User Agent matched blocking rule', $this->getContext($request, [
                'is_bot' => $this->deviceDetector->isBot(),
            ]));
        }

        return $result;
    }

    /**
     * Parse the UserAgent and create a Device Detector.
     *
     * @param string $userAgent
     *   The user agent to parse.
     *
     * @return DeviceDetector
     *   Return Device Detector.
     */
    protected function detectDevice(string $userAgent): DeviceDetector
    {
        AbstractDeviceParser::setVersionTruncation(AbstractDeviceParser::VERSION_TRUNCATION_NONE);
        $clientHints = ClientHints::factory($_SERVER);

        $selectiveDeviceDetector = new SelectiveDeviceDetector($userAgent, $clientHints);

        // Without this, device-detector recompiles its regex corpus — 20 YAML
        // files, 1.7MB — on the first parse of every PHP process. That costs
        // 110-637ms depending on the user agent, against ~4ms once warm, and
        // under PHP-FPM every worker pays it on its first request and again
        // after each `pm.max_requests` recycle (#107).
        $cache = $this->cache();

        if ($cache instanceof CacheInterface) {
            $selectiveDeviceDetector->setCache($cache);
        }

        // Stop at the deepest phase the configured rules actually read (#108).
        // A `bot:`-only config has no use for brand and model detection, which
        // is the dearest phase remaining once the corpus is cached.
        $selectiveDeviceDetector->parseUpTo($this->requiredPhase());

        return $selectiveDeviceDetector;
    }

    /**
     * The deepest parse phase the configured rules need.
     *
     * Cached per instance: the rules do not change between requests, and
     * walking them per request would give back some of what this saves.
     *
     * @return string
     *   One of the `SelectiveDeviceDetector::PHASE_*` constants.
     */
    protected function requiredPhase(): string
    {
        if ($this->requiredPhase !== null) {
            return $this->requiredPhase;
        }

        $deepest = self::VARIABLE_PHASES['bot'];

        foreach ($this->collectVariables($this->config) as $variable) {
            $phase = $this->phaseForVariable($variable);

            // Nothing is deeper than `device`, so stop looking.
            if ($phase === SelectiveDeviceDetector::PHASE_DEVICE) {
                $deepest = SelectiveDeviceDetector::PHASE_DEVICE;
                break;
            }

            if ($this->isDeeper($phase, $deepest)) {
                $deepest = $phase;
            }
        }

        $this->getLogger()->debug('User Agent parse depth resolved', [
            'phase' => $deepest,
        ]);

        return $this->requiredPhase = $deepest;
    }

    /**
     * Map a rule variable onto the phase that produces it.
     *
     * Unknown variables resolve to the deepest phase. `getValue()` returns
     * NULL for anything it does not recognise, so such a rule cannot match
     * either way — but guessing shallow on an unrecognised name is how a rule
     * silently stops matching after someone adds a variable here and forgets
     * to update this map.
     *
     * @param string $variable
     *   A rule variable, e.g. `client.name`.
     *
     * @return string
     *   The phase that must have run for it to be readable.
     */
    protected function phaseForVariable(string $variable): string
    {
        $root = strtolower(trim((string) ($this->splitQuery($variable)[0] ?? '')));

        return self::VARIABLE_PHASES[$root] ?? SelectiveDeviceDetector::PHASE_DEVICE;
    }

    /**
     * Pull every variable name out of a rule tree.
     *
     * Handles the three shapes `EvaluateTrait` accepts: a shorthand string, a
     * structured array with a `variable` key, and an `AND` / `OR` group with a
     * nested `rules` list. Anything else yields a sentinel that resolves to
     * the deepest phase, so an unfamiliar rule shape costs performance rather
     * than correctness.
     *
     * @param array<int|string, mixed> $rules
     *   Rules to walk.
     *
     * @return array<int, string>
     *   Variable names, with duplicates left in — the caller only takes a max.
     */
    protected function collectVariables(array $rules): array
    {
        $variables = [];

        foreach ($rules as $rule) {
            if (is_string($rule)) {
                $variables[] = $this->variableFromShorthand($rule);
                continue;
            }

            if (!is_array($rule)) {
                // Unrecognised: force the deepest phase.
                $variables[] = '';
                continue;
            }

            if (isset($rule['rules']) && is_array($rule['rules'])) {
                $variables = array_merge($variables, $this->collectVariables($rule['rules']));
                continue;
            }

            if (isset($rule['variable']) && is_string($rule['variable'])) {
                $variables[] = $rule['variable'];
                continue;
            }

            $variables[] = '';
        }

        return $variables;
    }

    /**
     * Read the variable out of a shorthand rule string.
     *
     * Mirrors the prefixes `EvaluateTrait::parseSimpleStringRule()` strips:
     * a leading `!` for negation, an `@operator` suffix, and the `>`/`<`
     * comparison shorthand. It only needs the variable, so it does not attempt
     * to parse the rest.
     *
     * @param string $rule
     *   A shorthand rule such as `!client.version@less_than:80`.
     *
     * @return string
     *   The variable name, or an empty string when the rule is malformed.
     */
    protected function variableFromShorthand(string $rule): string
    {
        $rule = ltrim(trim($rule), '!');

        // "variable@operator:value"
        if (str_contains($rule, '@')) {
            return trim(strstr($rule, '@', true) ?: '');
        }

        // "variable > value" and friends, checked before the ':' form because
        // this syntax carries no colon at all.
        if (preg_match('/^([^><:]+)\s*(?:>=|<=|>|<)/', $rule, $matches) === 1) {
            return trim($matches[1]);
        }

        // "variable:value"
        if (str_contains($rule, ':')) {
            return trim(strstr($rule, ':', true) ?: '');
        }

        return '';
    }

    /**
     * Is $candidate deeper in the parse order than $current?
     */
    protected function isDeeper(string $candidate, string $current): bool
    {
        $phases = SelectiveDeviceDetector::PHASES;

        return (array_search($candidate, $phases, true) ?: 0)
            > (array_search($current, $phases, true) ?: 0);
    }

    /**
     * The regex-corpus cache, built once per plugin instance.
     *
     * @return CacheInterface|null
     *   NULL when caching is disabled or the adaptor could not be built.
     */
    protected function cache(): ?CacheInterface
    {
        if ($this->cacheResolved) {
            return $this->cache;
        }

        $this->cacheResolved = true;
        $this->cache = $this->buildCache();

        return $this->cache;
    }

    /**
     * Resolve `metadata.cache` into a device-detector cache.
     *
     * Accepts, in order of precedence:
     *   - `false` — caching off.
     *   - An already-constructed PSR-6 pool, for callers wiring this from a
     *     framework container via config overrides.
     *   - `['adaptor' => class-string, 'args' => [...]]`, matching the shape
     *     `CacheRateLimitStorage` already uses so there is one convention
     *     rather than two.
     *   - Nothing — a filesystem cache under the shared firewall cache
     *     directory, following the `AbuseIpdb` precedent.
     *
     * Never throws. A cache is an optimisation, and a security plugin that
     * refuses to start because a cache directory is unwritable would be a
     * worse outcome than one that runs slowly.
     */
    protected function buildCache(): ?CacheInterface
    {
        $configured = $this->metadata['cache'] ?? null;

        // Explicit opt-out. Checked before the empty-ish cases below because
        // `false` and "not configured" mean different things here.
        if ($configured === false) {
            $this->getLogger()->debug('User Agent regex cache disabled by config');
            return null;
        }

        try {
            $pool = $this->cachePool($configured);
        } catch (\Throwable $throwable) {
            $this->getLogger()->warning('User Agent regex cache could not be created - detection will be slower', [
                'error' => $throwable->getMessage(),
                'hint'  => 'Point metadata.cache.args at a writable directory, or set metadata.cache: false to silence this.',
            ]);
            return null;
        }

        if (!$pool instanceof CacheItemPoolInterface) {
            return null;
        }

        // Constructing a pool proves nothing. FilesystemAdapter succeeds on an
        // unwritable directory and only fails later, per write — so without
        // this the plugin reported a healthy cache while every request paid
        // the full uncached parse, ~645ms, forever and silently.
        if (!$this->cacheIsUsable($pool)) {
            $this->getLogger()->warning(
                'User Agent regex cache is not writable - every request will re-parse the detection corpus',
                [
                    'pool' => $pool::class,
                    'impact' => 'Roughly 600ms per request instead of ~20ms.',
                    'hint' => 'Point metadata.cache.dir at a writable directory, define '
                        . 'KANOPI_FIREWALL_CACHE_DIR, or set metadata.cache: false to accept the cost silently.',
                ],
            );

            return null;
        }

        $this->getLogger()->debug('User Agent regex cache initialized', [
            'pool' => $pool::class,
        ]);

        return new PSR6Bridge($pool);
    }

    /**
     * Does this pool actually persist anything?
     *
     * A round trip rather than a permissions check: the pool may be a
     * filesystem directory, Redis, APCu or something a consumer injected, and
     * the only property that matters is whether a value written now can be
     * read back. Cheap — sub-millisecond on every backend — and it runs once
     * per plugin instance, not once per evaluation.
     *
     * @param CacheItemPoolInterface $cacheItemPool
     *   The pool to probe.
     *
     * @return bool
     *   TRUE when a written value came back.
     */
    protected function cacheIsUsable(CacheItemPoolInterface $cacheItemPool): bool
    {
        try {
            $item = $cacheItemPool->getItem('kanopi_firewall_cache_probe');
            $item->set(true);

            if (!$cacheItemPool->save($item)) {
                return false;
            }

            return $cacheItemPool->getItem('kanopi_firewall_cache_probe')->isHit();
        } catch (\Throwable $throwable) {
            $this->getLogger()->debug('User Agent regex cache probe threw', [
                'error' => $throwable->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Build the PSR-6 pool backing the cache.
     *
     * @param mixed $configured
     *   The raw `metadata.cache` value.
     *
     * @return CacheItemPoolInterface|null
     *   The pool, or NULL when the configuration names something unusable.
     */
    protected function cachePool(mixed $configured): ?CacheItemPoolInterface
    {
        if ($configured instanceof CacheItemPoolInterface) {
            return $configured;
        }

        $adaptor = is_array($configured) ? ($configured['adaptor'] ?? null) : null;

        if ($adaptor instanceof CacheItemPoolInterface) {
            return $adaptor;
        }

        if (is_string($adaptor) && $adaptor !== '') {
            if (!class_exists($adaptor) || !is_subclass_of($adaptor, CacheItemPoolInterface::class)) {
                $this->getLogger()->warning('User Agent cache adaptor is not a PSR-6 pool - falling back to the default', [
                    'adaptor' => $adaptor,
                ]);

                return $this->defaultPool();
            }

            $args = is_array($configured['args'] ?? null) ? $configured['args'] : [];

            return new $adaptor(...$args);
        }

        return $this->defaultPool();
    }

    /**
     * Filesystem cache under the shared firewall cache directory.
     *
     * On by default. The alternative — off unless configured — would mean
     * almost nobody gets the improvement, because the cost is invisible
     * without profiling. Writing to the system temp directory follows what
     * `AbuseIpdb` already does for its verdict cache.
     *
     * The namespace carries no version of its own: device-detector already
     * keys its entries by `DeviceDetector::VERSION`, so an upgrade
     * invalidates them without help from us.
     */
    protected function defaultPool(): CacheItemPoolInterface
    {
        return new FilesystemAdapter('device-detector', 0, $this->cacheDir());
    }

    /**
     * Directory holding the cached regex corpus.
     *
     * Mirrors `AbuseIpdb::cacheDir()` so a deployment that already sets
     * KANOPI_FIREWALL_CACHE_DIR does not have to say it twice.
     */
    protected function cacheDir(): string
    {
        $configured = is_array($this->metadata['cache'] ?? null)
            ? ($this->metadata['cache']['dir'] ?? null)
            : null;

        if (is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        if (defined('KANOPI_FIREWALL_CACHE_DIR')) {
            return (string) constant('KANOPI_FIREWALL_CACHE_DIR');
        }

        return sys_get_temp_dir() . '/kanopi-firewall-device-detector';
    }

    /**
     * Extract the value for a given variable name from the User Agent object.
     *
     * Supported variables:
     * - bot: Is the User Agent a Bot
     * - device: Type of the device
     * - client: Client information
     * - os: Type of OS being used
     * - brand: Device brand
     * - model: The model of the device
     *
     * @param Request $request
     *   Symfony HTTP request object.
     * @param string $variable
     *   Variable name to extract from the request.
     *
     * @return mixed
     *   The value of the variable or empty string if not found.
     */
    protected function getValue(Request $request, string $variable): mixed
    {
        $segments = $this->splitQuery($variable);

        if ($segments === []) {
            $this->getLogger()->warning('Empty variable provided for User Agent evaluation', $this->getContext($request, [
                'variable' => $variable,
            ]));
            return null;
        }

        $this->getLogger()->debug('Extracting User Agent variable', $this->getContext($request, [
            'variable' => $variable,
            'segments' => $segments,
        ]));

        switch (strtolower((string) $segments[0])) {
            case 'automated':
                // Any source. See the constant's docblock for why this is a
                // separate variable rather than a redefinition of `bot`.
                return $this->isAutomated() ? 'true' : 'false';
            case 'bot':
                if (count($segments) === 1) {
                    return $this->deviceDetector->isBot() ? 'true' : 'false';
                }

                $data = $this->deviceDetector->isBot() ? $this->deviceDetector->getBot() : [];
                break;
            case 'device':
                $data = ['type' => $this->deviceDetector->getDeviceName()];
                break;
            case 'client':
                $data = $this->deviceDetector->getClient(); // name, type, version
                break;
            case 'os':
                $data = $this->deviceDetector->getOs(); // name, short_name, version
                break;
            case 'brand':
                return $this->deviceDetector->getBrandName();
            case 'model':
                return $this->deviceDetector->getModel();
            default:
                return null;
        }

        // Traverse nested keys
        foreach (array_slice($segments, 1) as $segment) {
            if (!is_array($data) || !array_key_exists($segment, $data)) {
                return null;
            }

            $data = $data[$segment];
        }

        return is_string($data) ? $data : null;
    }

    /**
     * {@inheritdoc}
     *
     * Mirrors the switch in `getValue()`. `automated` is listed first because
     * it is the one people reach for and the one most often misspelled.
     */
    protected function knownRuleVariables(): array
    {
        return ['automated', 'bot', 'device', 'client', 'os', 'brand', 'model'];
    }
}
