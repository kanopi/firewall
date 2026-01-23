<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Kanopi\Firewall\Traits\EvaluateTrait;
use Kanopi\Firewall\Traits\GeoLocationTrait;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate the location of the request.
 */
class GeoLocation extends AbstractPluginBase
{
    use EvaluateTrait;
    use GeoLocationTrait;

    /**
     * Constructs a new GeoLocation object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);

        if ($this->reader === null) {
            $this->getLogger()->warning('GeoLocation reader not configured or failed to initialize', [
                'reader_type' => $metadata['reader']['type'] ?? 'none',
            ]);
        } else {
            $this->getLogger()->debug('GeoLocation reader initialized', [
                'reader_type' => $metadata['reader']['type'] ?? 'default',
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return "GeoLocation";
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription(): string
    {
        return "Evaluate the GeoLocation Details";
    }

    /**
     * {@inheritdoc}
     */
    public function evaluate(Request $request): bool
    {
        if ($this->reader === null) {
            $this->getLogger()->debug('GeoLocation evaluation skipped - no reader available', $this->getContext($request));
            return false;
        }

        $this->getLogger()->debug('GeoLocation evaluation started', $this->getContext($request));

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('GeoLocation matched blocking rule', $this->getContext($request));
        }

        return $result;
    }

    /**
     * Extract the value for a given variable name from the User Agent object.
     *
     * Supported variables:
     * - country: Country of the request
     * - continent: Continent of the request
     * - city: City of the request
     * - location: Location of the request
     * - postal: Postal Code
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
        if ($this->reader === null) {
            return false;
        }

        $parts = $this->splitQuery($variable);

        if ($parts === []) {
            $this->getLogger()->warning('Empty variable provided for GeoLocation evaluation', $this->getContext($request, [
                'variable' => $variable,
            ]));
            return null;
        }

        try {
            $clientIp = $request->getClientIp();
            $record = $this->reader->city($clientIp);

            $this->getLogger()->debug('GeoLocation lookup successful', $this->getContext($request, [
                'country' => $record->country->isoCode ?? 'unknown',
                'city' => $record->city->name ?? 'unknown',
                'variable' => $variable,
            ]));
        } catch (\Exception $exception) {
            $this->getLogger()->warning('GeoLocation lookup failed', $this->getContext($request, [
                'variable' => $variable,
                'error' => $exception->getMessage(),
            ]));
            return null;
        }

        return match ($parts[0]) {
            'country' => $record->country->{$parts[1] ?? 'isoCode'} ?? null,
            'continent' => $record->continent->{$parts[1] ?? 'code'} ?? null,
            'city' => $record->city->{$parts[1] ?? 'name'} ?? null,
            'location' => $record->location->{$parts[1] ?? ''} ?? null,
            'postal' => $record->postal->{$parts[1] ?? 'code'} ?? null,
            default => null,
        };
    }
}
