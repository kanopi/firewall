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
 * Reads the signals a CDN computes at the edge and the origin cannot (#206).
 *
 * A TLS fingerprint identifies the **client stack** rather than what it claims
 * to be, so it catches tooling wearing a browser's User-Agent -- the gap
 * reverse-DNS verification (#199) closes for crawlers, closed differently for
 * everything else. A bot score is the edge's own verdict, computed from signals
 * that never reach the origin at all.
 *
 * None of it is computed here. The edge already decided; this reads what it
 * decided, which is why the plugin is small and why it can do nothing without a
 * CDN in front of it.
 *
 * Header names differ per CDN, so the mapping lives here and is selected by
 * name -- the same shape `GeoHeaderMap` established for geolocation (#176).
 */
final class EdgeSignalMap
{
    /**
     * Providers with a known header layout.
     *
     * Two, and `custom`, on purpose. Cloudflare publishes documented header
     * names; Fastly exposes the values in VCL and leaves the naming to the
     * operator, so the names below are the ones the snippet in the docs sets.
     *
     * Akamai and CloudFront are deliberately absent rather than guessed at:
     * Akamai Bot Manager's response headers are configured per property, and
     * CloudFront computes no bot signal of its own. Both are reachable through
     * `custom`, which is the honest answer -- a named profile whose header
     * names were invented would be worse than no profile, because it would look
     * authoritative.
     */
    public const PROVIDERS = ['cloudflare', 'fastly', 'custom'];

    /**
     * Signals a provider can populate, in the rules' own vocabulary.
     */
    public const FIELDS = ['bot_score', 'verified_bot', 'ja3', 'ja4'];

    /**
     * Header names per provider.
     *
     * **None of these are present by default.** Cloudflare adds them through
     * Managed Transforms, which have to be switched on per zone, and a field
     * whose header is absent resolves to NULL rather than being guessed at.
     * That is the same posture `GeoHeaderMap` takes for everything except
     * `CF-IPCountry`.
     *
     * @var array<string, array<string, string>>
     */
    private const HEADERS = [
        'cloudflare' => [
            'bot_score' => 'Cf-Bot-Score',
            'verified_bot' => 'Cf-Verified-Bot',
            'ja3' => 'Cf-Ja3-Hash',
            'ja4' => 'Cf-Ja4',
        ],
        // Fastly adds no bot header of its own -- the values are available in
        // VCL as `tls.client.ja3_md5` and the bot signals its Bot Management
        // product exposes, and the operator decides what to call them. These
        // are the names the snippet in docs/plugins/edge-signals.md sets, so
        // the provider and the snippet match. An existing deployment with
        // different names uses `custom`.
        //
        // Deliberately not `Fastly-*`: Fastly uses that prefix for its own
        // headers, and squatting on it invites a collision.
        'fastly' => [
            'bot_score' => 'X-Edge-Bot-Score',
            'verified_bot' => 'X-Edge-Verified-Bot',
            'ja3' => 'X-Edge-Ja3',
            'ja4' => 'X-Edge-Ja4',
        ],
    ];

    /**
     * @param string $provider
     *   One of self::PROVIDERS.
     * @param array<string, string> $headers
     *   Field to header name.
     */
    private function __construct(
        private readonly string $provider,
        private readonly array $headers
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
                'EdgeSignal: metadata.provider must be one of %s, got %s.',
                implode(', ', self::PROVIDERS),
                is_string($provider) ? sprintf('"%s"', $provider) : gettype($provider)
            ));
        }

        $declared = $metadata['headers'] ?? [];

        if (!is_array($declared)) {
            throw new ConfigurationException(sprintf(
                'EdgeSignal: metadata.headers must be a map of signal to header name, %s given.',
                gettype($declared)
            ));
        }

        $headers = [];

        foreach ($declared as $field => $header) {
            if (!is_string($field) || !is_string($header) || trim($header) === '') {
                throw new ConfigurationException(
                    'EdgeSignal: metadata.headers entries must be signal: "Header-Name" pairs.'
                );
            }

            if (!in_array($field, self::FIELDS, true)) {
                throw new ConfigurationException(sprintf(
                    'EdgeSignal: unknown signal "%s" in metadata.headers. Known signals: %s.',
                    $field,
                    implode(', ', self::FIELDS)
                ));
            }

            $headers[$field] = trim($header);
        }

        // Declared names win over the profile's, so a zone that renamed one
        // header does not have to restate the other three.
        $headers += self::HEADERS[$provider] ?? [];

        if ($headers === []) {
            throw new ConfigurationException(sprintf(
                'EdgeSignal: metadata.provider is "custom" but metadata.headers names no headers, so '
                . 'there is nothing to read. Map at least one of %s.',
                implode(', ', self::FIELDS)
            ));
        }

        return new self($provider, $headers);
    }

    /**
     * Read every mapped signal the request actually carried.
     *
     * @param Request $request
     *   The request to read.
     *
     * @return array<string, string>
     *   Signal to value, omitting anything the edge did not send. An absent
     *   header is absent rather than empty: a rule comparing against it should
     *   not match, and `bot_score` defaulting to 0 would match every "block
     *   the obvious bots" rule ever written.
     */
    public function read(Request $request): array
    {
        $values = [];

        foreach ($this->headers as $field => $header) {
            $value = $request->headers->get($header);
            if (!is_string($value)) {
                continue;
            }

            if (trim($value) === '') {
                continue;
            }

            $values[$field] = trim($value);
        }

        return $values;
    }

    /**
     * Which provider this mapping is for.
     *
     * @return string
     *   The provider name, for a log line.
     */
    public function provider(): string
    {
        return $this->provider;
    }
}
