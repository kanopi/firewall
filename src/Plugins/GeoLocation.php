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
use Kanopi\Firewall\Utility\GeoHeaderMap;
use Symfony\Component\HttpFoundation\Request;

/**
 * Evaluate the location of the request.
 */
class GeoLocation extends AbstractPluginBase
{
    use EvaluateTrait;
    use GeoLocationTrait;

    /**
     * Where location comes from.
     */
    public const SOURCES = ['reader', 'header'];

    /**
     * Whether the operator configured a reader at all (vs. an init failure).
     */
    private bool $readerConfigured;

    /**
     * Header mapping, when reading location from the edge.
     */
    private ?GeoHeaderMap $geoHeaderMap = null;

    /**
     * Fields the edge sent for the request being evaluated.
     *
     * @var array<string, string>
     */
    private array $headerValues = [];

    /**
     * Constructs a new GeoLocation object.
     */
    public function __construct(array $metadata = [], array $config = [])
    {
        parent::__construct($metadata, $config);

        if ($this->source() === 'header') {
            $this->geoHeaderMap = GeoHeaderMap::fromMetadata($metadata);
            $this->readerConfigured = false;

            $this->getLogger()->debug('GeoLocation reading location from edge headers', [
                'provider' => $this->geoHeaderMap->provider(),
            ]);

            return;
        }

        $this->readerConfigured = isset($metadata['reader']);
        $this->reader = $this->createService($metadata['reader']['type'] ?? null, $metadata['reader'] ?? []);

        if ($this->reader === null) {
            // Init failure on a configured reader is a security-relevant
            // event. See Asn::__construct for rationale.
            $level = $this->readerConfigured ? 'error' : 'debug';
            $this->getLogger()->log($level, 'GeoLocation reader not available', [
                'reader_type' => $metadata['reader']['type'] ?? 'none',
                'reader_configured' => $this->readerConfigured,
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
    protected function defaultName(): string
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
    /**
     * Where this plugin reads location from.
     *
     * @return string
     *   One of self::SOURCES.
     */
    protected function source(): string
    {
        $source = $this->metadata['source'] ?? 'reader';

        if (is_string($source) && in_array($source, self::SOURCES, true)) {
            return $source;
        }

        if ($source !== 'reader') {
            $this->getLogger()->warning('Unknown GeoLocation source; falling back to the reader', [
                'source' => is_string($source) ? $source : gettype($source),
                'known' => implode(', ', self::SOURCES),
            ]);
        }

        return 'reader';
    }

    /**
     * Whether an edge header may be believed for this request.
     *
     * A geo header is a claim, and a claim is only worth anything when the
     * request provably came through the edge that makes it. Otherwise a request
     * straight to the origin can set `CF-IPCountry: US` and pick its own
     * country — and against a `response: allow` entry that is not a weakened
     * control but a complete bypass, since an allow match short-circuits
     * everything after it.
     *
     * Symfony already knows whether a request arrived via a trusted proxy, and
     * a deployment behind a CDN has to configure that anyway for
     * `getClientIp()` to be right. So that is the gate rather than a second
     * list to maintain.
     *
     * @param Request $request
     *   The request under evaluation.
     *
     * @return bool
     *   TRUE when the headers may be read.
     */
    protected function edgeIsTrusted(Request $request): bool
    {
        return $request->isFromTrustedProxy();
    }

    public function evaluate(Request $request): bool
    {
        if ($this->geoHeaderMap instanceof GeoHeaderMap) {
            return $this->evaluateFromHeaders($request);
        }

        if ($this->reader === null) {
            if (!$this->readerConfigured) {
                $this->getLogger()->debug('GeoLocation evaluation skipped - no reader configured', $this->getContext($request));
                return false;
            }

            $failOpen = (bool) ($this->metadata['fail_open'] ?? false);
            $this->getLogger()->error('GeoLocation reader unavailable - failing ' . ($failOpen ? 'open' : 'closed'), $this->getContext($request, [
                'fail_open' => $failOpen,
            ]));
            return !$failOpen;
        }

        $this->getLogger()->debug('GeoLocation evaluation started', $this->getContext($request));

        $result = $this->evaluateRequest($request, $this->config);

        if ($result) {
            $this->getLogger()->info('GeoLocation matched blocking rule', $this->getContext($request));
        }

        return $result;
    }

    /**
     * Resolve a rule variable from what the edge sent.
     *
     * The vocabulary is the reader's, so a rule written for a MaxMind-backed
     * plugin keeps working when the source changes. What the edge cannot supply
     * resolves to NULL rather than to a wrong answer — `country.name` is absent
     * on Cloudflare, for instance, while `country` is present on every plan.
     *
     * @param string $variable
     *   The rule variable, e.g. `country` or `location.latitude`.
     *
     * @return string|null
     *   The value, or NULL when the edge did not supply it.
     */
    protected function headerValue(string $variable): ?string
    {
        $field = strtolower(trim($variable));

        // `country` and `country.isoCode` ask the same question; the reader
        // path answers both, so this one does too.
        $aliases = [
            'country.isocode' => 'country',
            'continent.code' => 'continent',
            'city.name' => 'city',
            'postal.code' => 'postal',
        ];

        $field = $aliases[$field] ?? $field;

        foreach ($this->headerValues as $name => $value) {
            if (strcasecmp($name, $field) === 0) {
                return $value;
            }
        }

        return null;
    }

    /**
     * Evaluate the configured rules against the edge's geo headers.
     *
     * @param Request $request
     *   The request under evaluation.
     *
     * @return bool
     *   Whether a rule matched.
     */
    protected function evaluateFromHeaders(Request $request): bool
    {
        if (!$this->edgeIsTrusted($request)) {
            // Loud rather than quiet. Without trusted proxies configured this
            // plugin matches nothing, which looks exactly like "nobody from
            // those countries is visiting" — the failure #165 is about, in a
            // place where it means geo blocking is simply off.
            $this->getLogger()->warning(
                'GeoLocation is reading edge headers but this request did not arrive via a '
                . 'trusted proxy, so the headers are being ignored. Call '
                . 'Request::setTrustedProxies() with your CDN ranges, or the geo rules will '
                . 'never match.',
                $this->getContext($request, [
                    'provider' => $this->geoHeaderMap?->provider(),
                    'trusted_proxies' => Request::getTrustedProxies(),
                ])
            );

            return false;
        }

        $values = $this->geoHeaderMap?->read($request) ?? [];

        if ($values === []) {
            $this->getLogger()->debug('GeoLocation edge headers carried nothing', $this->getContext($request, [
                'provider' => $this->geoHeaderMap?->provider(),
            ]));

            return false;
        }

        $this->headerValues = $values;

        try {
            return $this->evaluateRequest($request, $this->config);
        } finally {
            $this->headerValues = [];
        }
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
        if ($this->geoHeaderMap instanceof GeoHeaderMap) {
            return $this->headerValue($variable);
        }

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
