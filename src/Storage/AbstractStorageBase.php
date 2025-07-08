<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Class for Storage Base.
 */
abstract class AbstractStorageBase implements StorageInterface
{
    use LoggingTrait;

    /**
     * Construct a new AbstractStorageBase object.
     *
     * @param array<string, mixed> $config
     *   Configuration details.
     */
    public function __construct(protected array $config = [])
    {
        $this->getLogger()->debug('Storage initialized', [
            'storage_type' => static::class,
            'config' => array_keys($config),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(Request $request): string
    {
        return strval($request->getClientIp());
    }

    /**
     * {@inheritdoc}
     */
    public function isBlocked(string $key): array|false
    {
        $data = $this->get($key, false);
        if ($data === false) {
            return false;
        }

        if (!is_array($data)) {
            return ['value' => $data];
        }

        return $data;
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
     * {@inheritdoc}
     */
    public function getStorageData(Request $request, ?PluginInterface $plugin): array
    {
        return [
            'plugin' => $plugin?->getName(),
            'event_id' => $request->attributes->get('x-request-id'),
            'timestamp' => date('c'),
            'request' => $this->serializeRequest($request),
        ];
    }
}
