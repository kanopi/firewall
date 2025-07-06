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
     * Create an object for use.
     *
     * @param string $type
     *   Type of reader to create.
     * @param array $config
     *   Configuration for reader.
     *
     * @return Reader|Client|null
     *   Return the created reader.
     */
    protected function createService(string $type, array $config = []): Reader|Client|null
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
