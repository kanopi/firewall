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
     * What this backend records about a request, built once.
     */
    private ?RecordedRequest $recordedRequest = null;

    /**
     * The policy deciding which request fields a block record keeps.
     *
     * Read from `storage.config.record_request`. Before 2.31.0 there was no
     * policy and the answer was everything, session cookie included (#375).
     *
     * @return RecordedRequest
     *   The policy.
     */
    protected function recordedRequest(): RecordedRequest
    {
        if (!$this->recordedRequest instanceof RecordedRequest) {
            $this->recordedRequest = RecordedRequest::fromConfig($this->config['record_request'] ?? null);
        }

        return $this->recordedRequest;
    }

    /**
     * Serialize relevant Symfony Request data.
     *
     * Filtered on the way *in*, which is the only place it can be. Redacting in
     * `bin/firewall-block`'s output would leave the credential in the store,
     * where `SharedStorage` replicates it across the fleet and a database backup
     * keeps it for as long as backups are kept.
     *
     * @param Request $request
     *   Request Information.
     *
     * @return array
     *   Return the structured data.
     */
    protected function serializeRequest(Request $request): array
    {
        return $this->recordedRequest()->serialize($request) + [
            // Names, types and sizes -- normalised by formatUploadedFiles() and
            // never content -- so there is nothing here an allowlist protects.
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
