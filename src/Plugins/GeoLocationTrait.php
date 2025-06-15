<?php

namespace Kanopi\Firewall\Plugins;

use GeoIp2\Database\Reader;
use GeoIp2\WebService\Client;
use MaxMind\Db\Reader\InvalidDatabaseException;

/**
 * GeoLocation Trait.
 */
trait GeoLocationTrait
{
    /**
     * Max Mind Database Reader.
     *
     * @var Reader|Client|null
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
        if (!file_exists($fileLocation)) {
            return null;
        }

        try {
            return new Reader($fileLocation);
        } catch (InvalidDatabaseException $e) {
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
        return new Client($accountId, $license, $locales, $options);
    }
}
