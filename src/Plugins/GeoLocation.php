<?php

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate the location of the request.
 */
class GeoLocation extends AbstractPluginBase
{
    use EvaluateTrait {
        getRequestValue as _getRequestValue;
    }

    use GeoLocationTrait;

    /**
     * Constructs a new GeoLocation object.
     */
    public function __construct(array $metadata, array $config = [])
    {
        parent::__construct($metadata, $config);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);
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
            return false;
        }
        return $this->evaluateRequest($request, $this->config);
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
    protected function getRequestValue(Request $request, string $variable): mixed
    {
        if ($this->reader === null) {
            return false;
        }

        $parts = explode('.', $variable);

        try {
            $record = $this->reader->city($request->getClientIp());
        } catch (\Exception $e) {
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
