<?php

declare(strict_types=1);

namespace Kanopi\Firewall;

use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Plugins\PluginManager;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Storage\StorageFactory;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Utility\NestedArray;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Yaml\Yaml;

/**
 * Firewall class that creates and evaluates requests.
 */
final readonly class Firewall
{
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
     * the default configuration loaded from `config.default.yml`.
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

        $default = Yaml::parse((string)@file_get_contents(__DIR__ . '/../config/config.default.yml'));

        $merged = $default;

        if (!is_array($merged)) {
            $merged = [];
        }

        /**
         * @param array<int, string|array<string, mixed>|null> $configs
         */
        foreach ($configs as $config) {
            if (is_string($config)) {
                if (!file_exists($config)) {
                    throw new \Exception('Config file does not exist: ' . $config);
                }

                $config = (array)Yaml::parse((string)@file_get_contents($config));
            } elseif (!is_array($config)) {
                $config = [];
            }

            // Merge current config into merged config
            /** @var array<string, mixed> $config */
            $merged = NestedArray::mergeDeepArray([$merged, $config]);
        }

        $propertyAccessor = PropertyAccess::createPropertyAccessorBuilder()
            ->getPropertyAccessor();

        foreach ($overrides as $key => $value) {
            try {
                $propertyAccessor->setValue($merged, $key, $value);
            } catch (\Exception) {
            }
        }

        // Set the default values.
        $merged['logger'] = isset($merged['logger']) && is_array($merged['logger']) ? $merged['logger'] : [];
        $merged['storage'] = isset($merged['storage']) && is_array($merged['storage']) ? $merged['storage'] : [];
        $merged['block'] = isset($merged['block']) && is_array($merged['block']) ? $merged['block'] : [];
        $merged['bypass'] = isset($merged['bypass']) && is_array($merged['bypass']) ? $merged['bypass'] : [];

        LoggingFactory::setLogger(LoggingFactory::create($merged['logger']));
        return new self(
            StorageFactory::create($merged['storage']),
            PluginManager::create($merged['block']),
            PluginManager::create($merged['bypass'])
        );
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
        // If PHP is running on cli mode.
        if (PHP_SAPI === 'cli') {
            return true;
        }

        if (is_null($request)) {
            $request = Request::createFromGlobals();
        }

        $request->attributes->set('x-request-id', $this->generateId($request));

        if ($this->bypassPluginManager->evaluate($request)) {
            return true;
        }

        if (($blocked = $this->isBlocked($request->getClientIp() ?? '')) !== false) {
            $plugin = '';
            if (is_array($blocked) && array_key_exists('plugin', $blocked)) {
                $plugin = $blocked['plugin'];
            }

            $this->sendBlockingResponse($request, $plugin);
        }

        $this->blockingPluginManager->evaluate($request, true, function ($block, $request, $plugin): void {
            /** @var bool $block */
            /** @var Request $request */
            /** @var PluginInterface $plugin */
            if ($block) {
                $this->blockIp($request, $plugin->getName());
                $this->sendBlockingResponse($request, $plugin->getName());
            }
        });

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
    private function generateId(Request $request): string
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
    private function isBlocked(string $ip): mixed
    {
        return $this->storage->get($ip, false);
    }

    /**
     * Block the IP Address against the database.
     *
     * @param Request $request
     *   Request information.
     * @param string $plugin
     *   Plugin that is blocking the IP Address.
     *
     * @return bool
     *   Return TRUE if successful, FALSE if issue.
     */
    private function blockIp(Request $request, string $plugin): bool
    {
        return $this->storage->set(
            $request->getClientIp(),
            [
                'plugin' => $plugin,
                'event_id' => $request->attributes->get('x-request-id'),
                'blocked' => date('c'),
                'request' => $this->serializeRequest($request),
            ]
        );
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
    private function serializeRequest(Request $request): array
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
            'server' => $request->server->all(),
            'content' => $request->getContent(),
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
    private function formatUploadedFiles(array $files): array
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
     * @param string $plugin
     *   Plugin name that is doing the blocking.
     */
    private function sendBlockingResponse(Request $request, string $plugin): never
    {
        http_response_code(406);
        exit(sprintf('%s %s %s', $request->attributes->get('x-request-id'), 'Banned', 'by ' . $plugin));
    }
}
