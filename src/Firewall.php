<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\HttpFoundation\Request;

/**
 * Firewall class that creates and evaluates requests.
 */
final class Firewall
{
    use LoggingTrait;

    /**
     * Create a new Firewall Object.
     *
     * @param StorageInterface $storage
     *   Storage to write data to.
     * @param PluginManager $blockingPluginManager
     *   Plugin manager for Blocking Plugins.
     * @param PluginManager $bypassPluginManager
     *   Plugin manager for Bypass Plugins.
     * @param array $config
     *   Global configuration that can be set as defaults.
     */
    protected function __construct(private StorageInterface $storage, private PluginManager $blockingPluginManager, private PluginManager $bypassPluginManager, private array $config)
    {
        $this->getLogger()->debug('Firewall instance created', [
            'storage_type' => $storage::class,
            'blocking_plugins_count' => count($blockingPluginManager->getPlugins()),
            'bypass_plugins_count' => count($bypassPluginManager->getPlugins()),
            'config_keys' => array_keys($config), // Log keys instead of full config to avoid sensitive data
        ]);
        $this->storage->expire();
    }

    /**
     * Creates a new instance of the class with a merged configuration.
     *
     * This method accepts zero or more configuration inputs. Each input can be:
     * - A string representing a path to a YAML configuration file, which will be parsed.
     * - An array containing configuration data.
     * - Null, which will be treated as an empty configuration.
     *
     * All configurations are merged in the order they are passed, layered on top of
     * the default configuration loaded from `config.yml`.
     *
     * @param array<int, string|array<string, mixed>|null> $configs
     *   Zero or more configurations to merge.
     *   Each can be a YAML file path (string), a config array, or null.
     * @param array<string, mixed> $overrides
     *   Override values of the configs.
     *
     * @return self
     *   A new instance of the class initialized with the merged config.
     *
     * @throws \Exception
     *   If a string argument does not reference an existing file,
     *   or if an argument is not string, array, or null.
     */
    public static function create(array $configs = [], array $overrides = []): self
    {
        // Load default config first
        $config = Config::load(array_merge([__DIR__ . '/../config/config.yml'], $configs), $overrides);

        // Set the default values.
        $config['logger'] = isset($config['logger']) && is_array($config['logger']) ? array_filter($config['logger']) : [];
        $config['storage'] = isset($config['storage']) && is_array($config['storage']) ? array_filter($config['storage']) : [];
        $config['block'] = isset($config['block']) && is_array($config['block']) ? array_filter($config['block']) : [];
        $config['bypass'] = isset($config['bypass']) && is_array($config['bypass']) ? array_filter($config['bypass']) : [];
        $config['global'] = isset($config['global']) && is_array($config['global']) ? array_filter($config['global']) : [];

        LoggingFactory::setLogger(LoggingFactory::create($config['logger']));

        $firewall = new self(
            StorageFactory::create($config['storage']),
            PluginManager::create($config['block']),
            PluginManager::create($config['bypass']),
            $config['global']
        );

        $firewall->getLogger()->debug('Firewall initialized', [
            'logger_config_keys' => array_keys($config['logger']),
            'storage_config_keys' => array_keys($config['storage']),
            'block_plugins' => array_keys($config['block']),
            'bypass_plugins' => array_keys($config['bypass']),
            'global_config_keys' => array_keys($config['global']),
        ]);

        return $firewall;
    }

    /**
     * Evaluate the current request to see if valid and can pass the firewall.
     *
     * @param \Symfony\Component\HttpFoundation\Request|null $request
     *   Request to evaluate.
     *
     * @return bool
     *   Return TRUE if allowed to pass. FALSE
     * @throws \Exception
     */
    public function evaluate(?Request $request = null): bool
    {
        // If PHP is running on cli mode skip.
        // @codeCoverageIgnoreStart
        if (PHP_SAPI === 'cli' && getenv('FIREWALL_TEST') !== '1') {
            $this->getLogger()->debug('CLI mode detected, bypassing firewall');
            return true;
        }

        // @codeCoverageIgnoreEnd

        if (is_null($request)) {
            $request = Request::createFromGlobals();
        }

        if (!$request->attributes->has('x-request-id')) {
            $requestId = $this->generateId($request);
            $request->attributes->set('x-request-id', $requestId);
            $this->getLogger()->debug('Request evaluation started', $this->getContext($request));
        }

        if (($plugin = $this->bypassPluginManager->evaluate($request)) !== false) {
            $this->getLogger()->info('Request bypassed', $this->getContext($request, [
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
            ]));
            return true;
        }

        if (($data = $this->storage->isBlocked($this->storage->getKey($request))) !== false) {
            if (array_key_exists('event_id', $data)) {
                $request->attributes->set('x-request-id', $data['event_id']);
            }

            $this->repeatOffender($request);
            $this->sendBlockingResponse($request, intval($this->config['repeat_offender_status'] ?? 0));
        }

        if (($plugin = $this->blockingPluginManager->evaluate($request)) !== false) {
            $this->block($request, $plugin);
            $this->sendBlockingResponse($request, $plugin->getStatusCode($request));
        }

        $this->getLogger()->debug('Request allowed', $this->getContext($request));

        return true;
    }

    /**
     * Action to acknowledge someone who has already been blocked.
     *
     * @param Request $request
     *   Request to evaluate.
     */
    protected function repeatOffender(Request $request): void
    {
        $addToExpire = intval($this->config['add_to_expire'] ?? 3600);
        if ($addToExpire > 0) {
            $this->storage->addToExpire($this->storage->getKey($request), $addToExpire);
        }

        $this->storage->recordOffense($this->storage->getKey($request));

        $this->getLogger()->debug('Repeat Offender', $this->getContext($request));
    }

    /**
     * Generate an ID for the following Request.
     *
     * @param Request $request
     *   Request to get information from.
     *
     * @return string
     *   Return the ID associated with the request.
     */
    protected function generateId(Request $request): string
    {
        return strtoupper(md5($request->getClientIp() . time()));
    }

    /**
     * Block the request and status code.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $statusCode
     *   Status code to return for the request.
     *
     * @throws \Exception
     *   When env variable is used for testing.
     */
    protected function sendBlockingResponse(Request $request, int $statusCode = 0): void
    {
        // Check to see if status code is 0 and a global config is set.
        if ($statusCode === 0 && array_key_exists('banning_status_code', $this->config) && is_int($this->config['banning_status_code'])) {
            $statusCode = intval($this->config['banning_status_code']);
        }

        // Fallback to setting status code to 400 if nothing is set.
        if ($statusCode === 0) {
            $statusCode = 400;
        }

        $this->getLogger()->notice('Sending blocking response', $this->getContext($request, [
            'status_code' => $statusCode,
        ]));

        // Replace variables in the custom message.
        $banningMessage = $this->interpolateTemplate(
            (
                (
                    array_key_exists('banning_message', $this->config) &&
                    is_string($this->config['banning_message'])
                ) ?
                $this->config['banning_message'] :
                "{{request.id}} Request Banned"
            ),
            $request
        );

        // Used for testing.
        if (getenv('FIREWALL_TEST') === '1') {
            throw new \Exception($banningMessage, $statusCode);
        }

        // @codeCoverageIgnoreStart
        http_response_code($statusCode);
        exit($banningMessage);
        // @codeCoverageIgnoreEnd
    }

    /**
     * Replace placeholders in a template string with values taken from a Symfony Request
     * and/or an additional context array.
     *
     * Supported placeholders (case-insensitive):
     *   • {{ request.method }}          →  GET / POST / …
     *   • {{ request.scheme }}          →  http / https
     *   • {{ request.host }}            →  example.com
     *   • {{ request.path }}            →  /search
     *   • {{ request.ip }}              →  client IP (trusts your Symfony trusted proxies config)
     *   • {{ request.header.X-Foo }}    →  any HTTP header
     *   • {{ request.query.q }}         →  ?q=something
     *   • {{ request.post.name }}       →  body fields (application/x-www-form-urlencoded, multipart, JSON parsed by you, …)
     *   • {{ request.cookie.session }}  →  cookies
     *
     * Any other placeholder is looked up verbatim in $context (e.g. {{ user_id }}).
     * Unknown placeholders are left untouched so you can chain calls safely.
     *
     * @param  string  $template
     *   The string containing {{ … }} placeholders
     * @param  Request $request
     *   The current Symfony Request
     * @param  array   $context
     *   Optional extra key/value pairs to interpolate
     *
     * @return string
     *   The interpolated result
     */
    protected function interpolateTemplate(string $template, Request $request, array $context = []): string
    {
        return strval(preg_replace_callback(
            '/\{\{\s*([a-zA-Z0-9_\.\-]+)\s*\}\}/',
            function (array $m) use ($request, $context) {
                $key = strtolower($m[1]);

                // 1. Built-in request values ------------------------------------
                switch ($key) {
                    case 'request.method':
                        return $request->getMethod();
                    case 'request.scheme':
                        return $request->getScheme();
                    case 'request.host':
                        return $request->getHost();
                    case 'request.path':
                        return $request->getPathInfo();
                    case 'request.ip':
                        return $request->getClientIp();
                    case 'request.id':
                        return $request->attributes->get('x-request-id');
                }

                // 2. request.header.<name>
                if (str_starts_with($key, 'request.header.')) {
                    $header = substr($key, 15);          // after 'request.header.'
                    return (string) $request->headers->get($header, '');
                }

                // 3. request.query.<param>
                if (str_starts_with($key, 'request.query.')) {
                    $param = substr($key, 14);
                    return (string) $request->query->get($param, '');
                }

                // 4. request.post.<param>  (body fields)
                if (str_starts_with($key, 'request.post.')) {
                    $param = substr($key, 13);
                    return (string) $request->request->get($param, '');
                }

                // 5. request.cookie.<name>
                if (str_starts_with($key, 'request.cookie.')) {
                    $param = substr($key, 15);
                    $cookies = array_change_key_case($request->cookies->all());
                    return strval($cookies[$param] ?? '');
                }

                // 6. Arbitrary context values ----------------------------------
                if (array_key_exists($m[1], $context)) {
                    return (string) $context[$m[1]];
                }

                // 7. Unknown placeholder – leave as-is so caller sees what was missing
                return $m[0];
            },
            $template
        ));
    }

    /**
     * Block the specific key.
     *
     * @param Request $request
     *   Request information.
     * @param PluginInterface $plugin
     *   Plugin that is blocking.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if there is an issue.
     */
    protected function block(Request $request, PluginInterface $plugin): bool
    {
        $this->getLogger()->warning('Request blocked by plugin', $this->getContext($request, [
            'plugin_name' => $plugin->getName(),
            'plugin_type' => $plugin::class,
            'status_code' => $plugin->getStatusCode($request),
        ]));

        $expirationTime = $this->determineExpirationTime(
            $request,
            $plugin->getExpirationTime($request)
        );

        $key = $this->storage->getKey($request);
        $value = $this->storage->getStorageData($request, $plugin);
        $success = $this->storage->set(
            $key,
            $value,
            $expirationTime
        );

        if ($success) {
            $this->getLogger()->info('IP blocked successfully', $this->getContext($request, [
                'key' => $key,
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
                'expiration_time' => $expirationTime,
            ]));
        } else {
            $this->getLogger()->error('Failed to block IP', $this->getContext($request, [
                'plugin_name' => $plugin->getName(),
                'plugin_type' => $plugin::class,
            ]));
        }

        return $success;
    }

    /**
     * Determine the expiration time based on the request and offenses.
     *
     * Escalation periods are written in an array/yaml format that look like:
     *
     * blocking_escalation:
     *   - window: 300
     *     offense: 1
     *   - window: 3600
     *     offense: 3
     *     duration: 3600
     *   - window: 86400
     *     offense: 5
     *     duration: 0
     *
     * Setting the window is how far back to look and count the number of offenses recorded. This is required.
     * Setting the offense is how many offenses we need to count to be able to bypass. If omitted, this defaults to 0.
     * Setting the duration is how many seconds the request should be banned for. Setting it to 0 means that it
     * should be permanently banned. Not setting this will use the default amount sent in from the plugin.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $initialTime
     *   Initial time.
     *
     * @return int
     *   Return the expiration time.
     */
    protected function determineExpirationTime(Request $request, int $initialTime = 0): int
    {
        if ($initialTime === 0) {
            return 0;
        }

        $now = time();

        $key = $this->storage->getKey($request);

        // Reverse the blocking_escalation elements to start from bottom and go up.
        $stages = array_reverse($this->config['blocking_escalation'] ?? [], true);
        foreach ($stages as $stage) {
            // Require the window amount to exist to acknowledge.
            if (!array_key_exists('window', $stage)) {
                continue;
            }

            $windowStart = $now - intval($stage['window']);
            $count = $this->storage->countOffenses($key, $windowStart, $now);

            if ($count >= intval($stage['offense'])) {
                return intval($stage['duration'] ?? $initialTime);
            }
        }

        if ($stages !== []) {
            return intval($stages[array_key_last($stages)]['duration'] ?? $initialTime);
        }

        return $initialTime;
    }
}
