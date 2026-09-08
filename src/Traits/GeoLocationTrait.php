<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use GeoIp2\Database\Reader;
use GeoIp2\WebService\Client;
use Kanopi\Firewall\Logging\LoggingTrait;
use MaxMind\Db\Reader\InvalidDatabaseException;

/**
 * GeoLocation Trait.
 */
trait GeoLocationTrait
{
    use LoggingTrait;

    /**
     * Max Mind Database Reader.
     */
    protected Reader|Client|null $reader = null;

    /**
     * Records already looked up during this request, keyed by method and address.
     *
     * `getValue()` is called once per rule variable, and each call did its own
     * database read -- so `country:US` and `city:London` in one rule set read the
     * same record twice, and `asn` alongside `asn_org` did the same (#6). The
     * record for one address cannot change within a request, so the second read
     * can never return anything different.
     *
     * @var array<string, object|null>
     */
    protected array $lookupMemo = [];

    /**
     * Look a record up once per address per request.
     *
     * A failed lookup is memoised as null and not retried, for the same reason a
     * successful one is not: nothing about the request changes between calls, so
     * a second attempt would fail identically while paying for it again.
     *
     * @param string $method
     *   Reader method to call -- `city` or `asn`.
     * @param string $clientIp
     *   Address to look up.
     *
     * @return object|null
     *   The record, or null when the lookup failed.
     */
    protected function lookupRecord(string $method, string $clientIp): ?object
    {
        $key = $method . ':' . $clientIp;

        if (array_key_exists($key, $this->lookupMemo)) {
            return $this->lookupMemo[$key];
        }

        if (!$this->reader instanceof Reader && !$this->reader instanceof Client) {
            return $this->lookupMemo[$key] = null;
        }

        if (!method_exists($this->reader, $method)) {
            return $this->lookupMemo[$key] = null;
        }

        $record = $this->reader->{$method}($clientIp);

        return $this->lookupMemo[$key] = is_object($record) ? $record : null;
    }

    /**
     * Create an object for use.
     *
     * @param string|null $type
     *   Type of reader to create.
     * @param array $config
     *   Configuration for reader.
     *
     * @return Reader|Client|null
     *   Return the created reader.
     */
    protected function createService(?string $type, array $config = []): Reader|Client|null
    {
        return match ($type) {
            'reader' => $this->getReader($config['db'] ?? ''),
            'client' => $this->getClient(
                $config['accountId'],
                $config['licenseKey'],
                $config['language'] ?? ['en'],
                $config['options'] ?? [],
            ),
            default => null,
        };
    }

    /**
     * Return the Reader Element.
     *
     * @param string $fileLocation
     *   Location of the Database
     *
     * @return Reader|null
     *   Return the new Reader object.
     */
    protected function getReader(string $fileLocation): ?Reader
    {
        if (!is_file($fileLocation) || !file_exists($fileLocation)) {
            $this->getLogger()->warning('GeoLocation database file not found', [
                'file' => $fileLocation,
            ]);
            return null;
        }

        try {
            $reader = new Reader($fileLocation);

            $this->getLogger()->debug('GeoLocation reader created', [
                'file' => $fileLocation,
                'file_size' => filesize($fileLocation),
            ]);

            return $reader;
        } catch (InvalidDatabaseException $invalidDatabaseException) {
            $this->getLogger()->error('Invalid GeoLocation database', [
                'file' => $fileLocation,
                'error' => $invalidDatabaseException->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * Return a new Web Service Client.
     *
     * @param int $accountId
     *   Account ID for the web service.
     * @param string $license
     *   License ID for the web service.
     * @param array $locales
     *   Array of locales to pass in.
     * @param array $options
     *   Additional Options to pass in.
     *
     * @return Client
     *   Web service client.
     */
    protected function getClient(int $accountId, string $license, array $locales = ['en'], array $options = []): Client
    {
        $client = new Client($accountId, $license, $locales, $options);

        $this->getLogger()->debug('GeoLocation web service client created', [
            'account_id' => $accountId,
            'locales' => $locales,
        ]);

        return $client;
    }
}
