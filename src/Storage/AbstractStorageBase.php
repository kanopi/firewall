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
    public function isBlocked(Request $request, int $addToExpire = 0): bool
    {
        $blocked = $this->get($request);

        if (is_null($blocked)) {
            return false;
        }

        $request->attributes->set('x-request-id', $blocked['event_id'] ?? '');
        $this->getLogger()->warning(
            'Request from blocked IP',
            array_merge(
                [
                    'request_id' => $request->attributes->get('x-request-id'),
                    'client_ip' => $request->getClientIp(),
                ],
                $blocked
            )
        );
        $this->addToExpire($request, $addToExpire);
        $this->recordOffense($request);
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function blockIp(Request $request, PluginInterface $plugin): bool
    {
        $this->getLogger()->warning('Request blocked by plugin', [
            'request_id' => $request->attributes->get('x-request-id'),
            'client_ip' => $request->getClientIp(),
            'plugin' => $plugin->getName(),
            'status_code' => $plugin->getStatusCode($request),
            'path' => $request->getPathInfo(),
            'query' => $request->query->all(),
            'user_agent' => $request->headers->get('User-Agent') ?? 'unknown',
        ]);

        $request->attributes->set('blocking-plugin', $plugin);
        $expirationTime = $this->determineExpirationTime(
            $request,
            $plugin->getExpirationTime($request)
        );

        $success = $this->set(
            $request,
            $expirationTime,
        );

        if ($success) {
            $this->getLogger()->info('IP blocked successfully', [
                'request_id' => $request->attributes->get('x-request-id'),
                'client_ip' => $request->getClientIp(),
                'plugin' => $plugin->getName(),
                'expiration_time' => $expirationTime,
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
     * Determine the expiration time based on the request and offenses.
     *
     * @param Request $request
     *   Request to evaluate.
     * @param int $initialTime
     *   Initial time.
     *
     * @return int
     *   Return the expiration time.
     */
    protected function determineExpirationTime(Request $request, int $initialTime): int
    {
        if ($initialTime === 0) {
            return 0;
        }

        $now = time();

        $stages = array_reverse($this->config['blocking_escalation'] ?? [], true);
        foreach ($stages as $stage) {
            $windowStart = $now - intval($stage['window']);
            $count = $this->countOffenses($request, $windowStart, $now);

            if ($count >= intval($stage['offense'])) {
                return intval($stage['duration'] ?? $initialTime);
            }
        }

        return intval($stages[0]['duration'] ?? $initialTime);
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
    final protected function serializeRequest(Request $request): array
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
    final protected function formatUploadedFiles(array $files): array
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
     * Standard function for returning default data to store blocked request.
     *
     * @param Request $request
     *   Request to get information from.
     * @param PluginInterface|null $plugin
     *   Plugin that is doing the blocking.
     *
     * @return array
     *   Information to return.
     */
    protected function getBlockingData(Request $request, ?PluginInterface $plugin): array
    {
        return [
            'plugin' => $plugin?->getName(),
            'event_id' => $request->attributes->get('x-request-id'),
            'timestamp' => date('c'),
            'request' => $this->serializeRequest($request),
        ];
    }
}
