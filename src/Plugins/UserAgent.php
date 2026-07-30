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

        $deviceDetector = new DeviceDetector($userAgent, $clientHints);

        // Without this, device-detector recompiles its regex corpus — 20 YAML
        // files, 1.7MB — on the first parse of every PHP process. That costs
        // 110-637ms depending on the user agent, against ~4ms once warm, and
        // under PHP-FPM every worker pays it on its first request and again
        // after each `pm.max_requests` recycle (#107).
        $cache = $this->cache();

        if ($cache instanceof CacheInterface) {
            $deviceDetector->setCache($cache);
        }

        $deviceDetector->parse();
        return $deviceDetector;
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

        $this->getLogger()->debug('User Agent regex cache initialized', [
            'pool' => $pool::class,
        ]);

        return new PSR6Bridge($pool);
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
}
