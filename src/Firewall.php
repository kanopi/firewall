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
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Kanopi\Firewall\Utility\Config;
use Symfony\Component\HttpFoundation\Request;

/**
 * Firewall class that creates and evaluates requests.
 */
final readonly class Firewall
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
     */
    protected function __construct(private StorageInterface $storage, private PluginManager $blockingPluginManager, private PluginManager $bypassPluginManager)
    {
        $this->getLogger()->debug('Firewall instance created', [
            'storage_type' => $storage::class,
            'blocking_plugins_count' => count($blockingPluginManager->getPlugins()),
            'bypass_plugins_count' => count($bypassPluginManager->getPlugins()),
        ]);
        $this->storage->clearExpire();
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

        LoggingFactory::setLogger(LoggingFactory::create($config['logger']));

        $firewall = new self(
            StorageFactory::create($config['storage']),
            PluginManager::create($config['block']),
            PluginManager::create($config['bypass'])
        );

        $firewall->getLogger()->info('Firewall initialized', [
            'logger_config' => $config['logger'],
            'storage_config' => $config['storage'],
            'block_plugins' => array_keys($config['block']),
            'bypass_plugins' => array_keys($config['bypass']),
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
            $this->getLogger()->debug('Request evaluation started', [
                'request_id' => $requestId,
                'client_ip' => $request->getClientIp(),
                'method' => $request->getMethod(),
                'path' => $request->getPathInfo(),
                'user_agent' => $request->headers->get('User-Agent'),
            ]);
        }

        if ($this->bypassPluginManager->evaluate($request)) {
            $this->getLogger()->info('Request bypassed', [
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'path' => $request->getPathInfo(),
            ]);
            return true;
        }

        if (($blocked = $this->isBlocked($request->getClientIp() ?? '')) !== false) {
            $request->attributes->set('x-request-id', $blocked['event_id'] ?? '');
            $this->getLogger()->warning('Request from blocked IP', [
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'original_plugin' => $blocked['plugin'] ?? 'unknown',
                'blocked_since' => $blocked['blocked'] ?? 'unknown',
            ]);
            $this->storage->addToExpire($request->getClientIp() ?? '', 300);
            $this->sendBlockingResponse($request);
        }

        $this->blockingPluginManager->evaluate($request, true, function ($block, $request, $plugin): void {
            /** @var bool $block */
            /** @var Request $request */
            /** @var PluginInterface $plugin */
            if ($block) {
                $this->getLogger()->warning('Request blocked by plugin', [
                    'request_id' => $request->attributes->get('x-request-id'),
                    'client_ip' => $request->getClientIp(),
                    'plugin' => $plugin->getName(),
                    'status_code' => $plugin->getStatusCode($request),
                    'path' => $request->getPathInfo(),
                    'query' => $request->query->all(),
                    'user_agent' => $request->headers->get('User-Agent') ?? 'unknown',
                ]);
                $this->blockIp($request, $plugin);
                $this->sendBlockingResponse($request, $plugin->getStatusCode($request));
            }
        });

        $this->getLogger()->debug('Request allowed', [
            'request_id' => $request->attributes->get('x-request-id'),
            'client_ip' => $request->getClientIp(),
            'path' => $request->getPathInfo(),
        ]);

        return true;
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
     * Check to see if the IP address is currently blocked.
     *
     * @param string $ip
     *   IP address to check against.
     *
     * @return mixed
     *   Return array of items if found, False if issues.
     */
    protected function isBlocked(string $ip): mixed
    {
        return $this->storage->get($ip, false);
    }

    /**
     * Block the IP Address against the database.
     *
     * @param Request $request
     *   Request information.
     * @param PluginInterface $plugin
     *   Plugin that is blocking the IP Address.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issue.
     */
    protected function blockIp(Request $request, PluginInterface $plugin): bool
    {
        $success = $this->storage->set(
            $request->getClientIp(),
            [
                'plugin' => $plugin->getName(),
                'event_id' => $request->attributes->get('x-request-id'),
                'blocked' => date('c'),
                'request' => $this->serializeRequest($request),
            ],
            $plugin->getExpirationTime($request)
        );

        if ($success) {
            $this->getLogger()->info('IP blocked successfully', [
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'plugin' => $plugin->getName(),
                'expiration_time' => $plugin->getExpirationTime($request),
            ]);
        } else {
            $this->getLogger()->error('Failed to block IP', [
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'plugin' => $plugin->getName(),
            ]);
        }

        return $success;
    }

    /**
     * Serialize relevant Symfony Request data.
     *
     * @param Request $request
     *   Request Information.
     *
     * @return array
     *   Return the structured data.
     */
    protected function serializeRequest(Request $request): array
    {
        return [
            'method' => $request->getMethod(),
            'uri' => $request->getUri(),
            'path' => $request->getPathInfo(),
            'query' => $request->query->all(),
            'request' => $request->request->all(),
            'headers' => $request->headers->all(),
            'cookies' => $request->cookies->all(),
            'files' => $this->formatUploadedFiles($request->files->all()),
            // @todo evaluate as possible debug parameters.
            // 'server' => $request->server->all(),
            // 'content' => $request->getContent(),
        ];
    }

    /**
     * Normalize uploaded files so they can be safely serialized.
     *
     * @param array $files
     *   List of all the file items.
     *
     * @return array
     *   Files structured.
     */
    protected function formatUploadedFiles(array $files): array
    {
        $normalized = [];

        foreach ($files as $key => $file) {
            if (is_array($file)) {
                $normalized[$key] = $this->formatUploadedFiles($file);
            } elseif ($file instanceof UploadedFile) {
                $normalized[$key] = [
                    'originalName' => $file->getClientOriginalName(),
                    'mimeType' => $file->getClientMimeType(),
                    'size' => $file->getSize(),
                    'error' => $file->getError(),
                    // optionally store file contents as base64 (use with caution)
                    // 'content' => base64_encode(file_get_contents($file->getPathname())),
                ];
            } else {
                $normalized[$key] = null;
            }
        }

        return $normalized;
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
    protected function sendBlockingResponse(Request $request, int $statusCode = 400): void
    {
        $this->getLogger()->notice('Sending blocking response', [
            'request_id' => $request->attributes->get('x-request-id'),
            'status_code' => $statusCode,
            'client_ip' => $request->getClientIp(),
        ]);

        // Used for testing.
        if (getenv('FIREWALL_TEST') === '1') {
            throw new \Exception(
                sprintf('%s %s', $request->attributes->get('x-request-id'), 'Request Banned'),
                $statusCode
            );
        }

        // @codeCoverageIgnoreStart
        http_response_code($statusCode);
        exit(sprintf('%s %s', $request->attributes->get('x-request-id'), 'Request Banned'));
        // @codeCoverageIgnoreEnd
    }
}
