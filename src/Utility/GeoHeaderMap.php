<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use Kanopi\Firewall\Exception\ConfigurationException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reads geolocation from the headers a CDN adds at the edge.
 *
 * A CDN has already done the lookup by the time a request reaches the origin,
 * so a site behind one can answer `country:CN` without shipping, updating, or
 * paying for a MaxMind database. What it gets back is thinner — country is
 * usually all that is present by default — so this is an alternative source for
 * the same variables rather than a replacement for the reader.
 *
 * Header names differ per CDN and Akamai's is a compound string rather than a
 * value, so the mapping lives here and is selected by name.
 */
final class GeoHeaderMap
{
    /**
     * Providers with a known header layout.
     */
    public const PROVIDERS = ['cloudflare', 'cloudfront', 'akamai', 'custom'];

    /**
     * Fields a provider can populate, in the plugin's own vocabulary.
     */
    public const FIELDS = [
        'country',
        'country.name',
        'continent',
        'city',
        'postal',
        'region',
        'location.latitude',
        'location.longitude',
    ];

    /**
     * Header names per provider.
     *
     * Only the first entry of each is present by default. Cloudflare emits
     * `CF-IPCountry` on every plan and the rest only once the corresponding
     * Managed Transform is enabled; CloudFront emits nothing until the viewer
     * headers are added to the cache or origin-request policy. A field whose
     * header is absent resolves to NULL rather than guessing.
     *
     * @var array<string, array<string, string>>
     */
    private const HEADERS = [
        'cloudflare' => [
            'country' => 'CF-IPCountry',
            'continent' => 'CF-IPContinent',
            'city' => 'CF-IPCity',
            'postal' => 'CF-Postal-Code',
            'region' => 'CF-Region-Code',
            'location.latitude' => 'CF-IPLatitude',
            'location.longitude' => 'CF-IPLongitude',
        ],
        'cloudfront' => [
            'country' => 'CloudFront-Viewer-Country',
            'country.name' => 'CloudFront-Viewer-Country-Name',
            'city' => 'CloudFront-Viewer-City',
            'postal' => 'CloudFront-Viewer-Postal-Code',
            'region' => 'CloudFront-Viewer-Country-Region',
            'location.latitude' => 'CloudFront-Viewer-Latitude',
            'location.longitude' => 'CloudFront-Viewer-Longitude',
        ],
    ];

    /**
     * Akamai packs everything into one header, as `key=value` pairs.
     */
    private const AKAMAI_HEADER = 'X-Akamai-Edgescape';

    /**
     * Akamai's key names, mapped to the plugin's vocabulary.
     *
     * @var array<string, string>
     */
    private const AKAMAI_KEYS = [
        'country_code' => 'country',
        'region_code' => 'region',
        'city' => 'city',
        'zip' => 'postal',
        'lat' => 'location.latitude',
        'long' => 'location.longitude',
        'continent' => 'continent',
    ];

    /**
     * @param string $provider
     *   One of self::PROVIDERS.
     * @param array<string, string> $headers
     *   Field to header name, for the `custom` provider.
     */
    private function __construct(
        private readonly string $provider,
        private readonly array $headers,
    ) {
    }

    /**
     * Build a mapping from plugin metadata.
     *
     * @param array<array-key, mixed> $metadata
     *   The plugin's metadata.
     *
     * @return self
     *   The mapping.
     *
     * @throws ConfigurationException
     *   When the provider is unknown, or `custom` names no usable headers.
     */
    public static function fromMetadata(array $metadata): self
    {
        $provider = $metadata['provider'] ?? 'custom';

        if (!is_string($provider) || !in_array($provider, self::PROVIDERS, true)) {
            throw new ConfigurationException(sprintf(
                'GeoLocation: metadata.provider must be one of %s, got %s.',
                implode(', ', self::PROVIDERS),
                is_string($provider) ? sprintf('"%s"', $provider) : gettype($provider)
            ));
        }

        $declared = $metadata['headers'] ?? [];

        if (!is_array($declared)) {
            throw new ConfigurationException(sprintf(
                'GeoLocation: metadata.headers must be a map of field to header name, %s given.',
                gettype($declared)
            ));
        }

        $headers = [];

        foreach ($declared as $field => $header) {
            if (!is_string($field) || !is_string($header) || trim($header) === '') {
                throw new ConfigurationException(
                    'GeoLocation: metadata.headers entries must be field: "Header-Name" pairs.'
                );
            }

            if (!in_array($field, self::FIELDS, true)) {
                throw new ConfigurationException(sprintf(
                    'GeoLocation: unknown geo field "%s" in metadata.headers. Known fields: %s.',
                    $field,
                    implode(', ', self::FIELDS)
                ));
            }

            $headers[$field] = trim($header);
        }

        // Fastly is the reason `custom` exists: it adds no geo header of its
        // own, so an operator sets one in VCL and names it here.
        if ($provider === 'custom' && $headers === []) {
            throw new ConfigurationException(
                'GeoLocation: metadata.provider "custom" needs metadata.headers naming at least one '
                . 'header. Fastly and most other edges add no geo header unless configured to.'
            );
        }

        return new self($provider, $headers);
    }

    /**
     * Read every field this provider can supply from a request.
     *
     * @param Request $request
     *   The request to read.
     *
     * @return array<string, string>
     *   Field to value, omitting anything the request did not carry.
     */
    public function read(Request $request): array
    {
        $values = $this->provider === 'akamai'
            ? $this->readAkamai($request)
            : $this->readNamed($request);

        // An explicit `headers` map always wins, so a provider's default can be
        // overridden one header at a time rather than all or nothing.
        foreach ($this->headers as $field => $header) {
            $value = $request->headers->get($header);

            if (is_string($value) && trim($value) !== '') {
                $values[$field] = trim($value);
            }
        }

        return $values;
    }

    /**
     * The provider this mapping reads.
     *
     * @return string
     *   One of self::PROVIDERS.
     */
    public function provider(): string
    {
        return $this->provider;
    }

    /**
     * Read a provider whose fields each have their own header.
     *
     * @param Request $request
     *   The request to read.
     *
     * @return array<string, string>
     *   Field to value.
     */
    private function readNamed(Request $request): array
    {
        $values = [];

        foreach (self::HEADERS[$this->provider] ?? [] as $field => $header) {
            $value = $request->headers->get($header);

            if (is_string($value) && trim($value) !== '') {
                $values[$field] = trim($value);
            }
        }

        return $values;
    }

    /**
     * Unpack Akamai's compound Edgescape header.
     *
     * Arrives as `georegion=263,country_code=US,region_code=CA,city=SANJOSE,
     * lat=37.3,long=-121.9`. Unknown keys are ignored rather than rejected —
     * Akamai adds fields over time and an unrecognised one should not cost the
     * fields that were understood.
     *
     * @param Request $request
     *   The request to read.
     *
     * @return array<string, string>
     *   Field to value.
     */
    private function readAkamai(Request $request): array
    {
        $raw = $request->headers->get(self::AKAMAI_HEADER);

        if (!is_string($raw) || trim($raw) === '') {
            return [];
        }

        $values = [];

        foreach (explode(',', $raw) as $pair) {
            if (!str_contains($pair, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $pair, 2);
            $field = self::AKAMAI_KEYS[strtolower(trim($key))] ?? null;

            if ($field !== null && trim($value) !== '') {
                $values[$field] = trim($value);
            }
        }

        return $values;
    }
}
