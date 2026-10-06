<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility\ReverseDns;

use Kanopi\Firewall\Exception\ConfigurationException;

/**
 * Lookups over DNS over HTTPS, each with a hard time limit (#473).
 *
 * The reason it exists: PHP's own lookups cannot be given a timeout, so on a host without a
 * local caching resolver one slow nameserver holds a worker for up to ten seconds. A curl
 * request can be given one, so this bounds every lookup at `timeout_ms`.
 *
 * Usually reached through a provider -- every built-in provider is this class with an
 * operator's settings -- but it can be named directly with `resolver_options`:
 *
 * ```yaml
 * global:
 *   reverse_dns:
 *     resolver: "Kanopi\\Firewall\\Utility\\ReverseDns\\DnsOverHttpResolver"
 *     resolver_options:
 *       endpoint: "https://resolver.internal/dns-query?name={{ dns.name }}&type={{ dns.type }}"
 *       address: 10.0.0.53
 * ```
 *
 * Options:
 * - `endpoint` (required): an `EndpointTemplate`.
 * - `address`: the IP to connect to, so the endpoint's own hostname is never looked up
 *   through the operating system's resolver -- which would bring back the stall this class
 *   exists to remove. The certificate is still checked against the endpoint's hostname.
 * - `headers`: request headers. Defaults to `Accept: application/dns-json`.
 * - `response`: a `ResponseReader` layout. Defaults to `dns-json`.
 * - `timeout_ms`: the limit on each lookup, connecting included. Defaults to 300. Usually set
 *   through the shared `global.reverse_dns.timeout_ms` rather than here.
 *
 * Requires the curl extension; without it the configuration is refused at startup.
 */
class DnsOverHttpResolver implements ReverseDnsResolverInterface
{
    /**
     * Default limit on each lookup, in milliseconds.
     */
    public const DEFAULT_TIMEOUT_MS = 300;

    /**
     * The longest limit accepted. Longer than this is not a bound worth having on the
     * request path.
     */
    public const MAX_TIMEOUT_MS = 10000;

    /**
     * Options this class takes.
     *
     * @var list<string>
     */
    private const OPTIONS = ['endpoint', 'address', 'headers', 'response', 'timeout_ms'];

    /**
     * One handle per process, so the connection -- and its TLS handshake -- is reused across
     * lookups and requests.
     */
    private static ?\CurlHandle $curlHandle = null;

    /**
     * Where to send lookups.
     */
    private readonly EndpointTemplate $endpointTemplate;

    /**
     * How to read the answers.
     */
    private readonly ResponseReader $responseReader;

    /**
     * The address to connect to, or NULL to resolve the endpoint's host.
     */
    private readonly ?string $address;

    /**
     * Request headers, as `Name: value` lines.
     *
     * @var list<string>
     */
    private readonly array $headers;

    /**
     * Limit on each lookup.
     */
    private readonly int $timeoutMs;

    /**
     * @param array<string, mixed> $options
     *   See the class description.
     *
     * @throws ConfigurationException
     *   For options that cannot be used.
     */
    public function __construct(array $options = [])
    {
        $problems = self::problems($options);

        if ($problems !== []) {
            throw new ConfigurationException(implode('; ', $problems));
        }

        $this->endpointTemplate = EndpointTemplate::fromConfig($options['endpoint']);
        $this->responseReader = ResponseReader::fromConfig($options['response'] ?? null);
        $this->address = is_string($options['address'] ?? null) ? $options['address'] : null;
        $this->timeoutMs = (int) ($options['timeout_ms'] ?? self::DEFAULT_TIMEOUT_MS);

        $headers = is_array($options['headers'] ?? null) ? $options['headers'] : ['Accept' => 'application/dns-json'];
        $lines = [];

        foreach ($headers as $name => $value) {
            // Both strings already: problems() refuses anything else.
            if (is_string($name) && is_string($value)) {
                $lines[] = $name . ': ' . $value;
            }
        }

        $this->headers = $lines;
    }

    /**
     * Everything wrong with a set of options, without building anything.
     *
     * @param array<array-key, mixed> $options
     *   The options.
     *
     * @return list<string>
     *   Problems, empty when they can be used.
     */
    public static function problems(array $options): array
    {
        $problems = [];

        if (!static::curlAvailable()) {
            $problems[] = 'DnsOverHttpResolver needs the curl extension, which is not loaded';
        }

        foreach (array_diff(array_map(strval(...), array_keys($options)), self::OPTIONS) as $unknown) {
            $problems[] = sprintf('unknown option "%s"; the options are %s', $unknown, implode(', ', self::OPTIONS));
        }

        if (!array_key_exists('endpoint', $options)) {
            $problems[] = 'endpoint is required';
        } else {
            foreach (EndpointTemplate::problems($options['endpoint']) as $problem) {
                $problems[] = 'endpoint: ' . $problem;
            }
        }

        foreach (ResponseReader::problems($options['response'] ?? null) as $problem) {
            $problems[] = 'response: ' . $problem;
        }

        if (array_key_exists('address', $options)) {
            $address = $options['address'];

            if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP) === false) {
                $problems[] = 'address must be an IP address';
            }
        }

        if (array_key_exists('headers', $options)) {
            $headers = $options['headers'];

            if (!is_array($headers)) {
                $problems[] = 'headers must be a map of header names to values';
            } else {
                foreach ($headers as $name => $value) {
                    if (!is_string($name) || preg_match('/^[A-Za-z0-9-]+$/', $name) !== 1 || !is_string($value) || preg_match('/[\r\n]/', $value) === 1) {
                        $problems[] = sprintf('headers: "%s" is not a usable header', is_string($name) ? $name : (string) $name);
                    }
                }
            }
        }

        if (array_key_exists('timeout_ms', $options)) {
            $timeout = $options['timeout_ms'];

            if (!is_int($timeout) || $timeout < 1 || $timeout > self::MAX_TIMEOUT_MS) {
                $problems[] = sprintf('timeout_ms must be a whole number of milliseconds from 1 to %d', self::MAX_TIMEOUT_MS);
            }
        }

        return $problems;
    }

    /**
     * {@inheritdoc}
     */
    public function reverse(string $ip): LookupResult
    {
        return $this->lookup($this->endpointTemplate->ptrUrl($ip), 'PTR');
    }

    /**
     * {@inheritdoc}
     *
     * The client address is not part of the interface's forward lookup, so
     * `{{ client.ip }}` and `{{ client.ip_arpa }}` are empty in a forward template.
     */
    public function forward(string $hostname, string $type): LookupResult
    {
        return $this->lookup($this->endpointTemplate->forwardUrl($hostname, $type, ''), $type);
    }

    /**
     * The endpoint's host, for reporting where lookups go.
     */
    public function host(): string
    {
        return $this->endpointTemplate->host();
    }

    /**
     * The address lookups connect to, if pinned.
     */
    public function address(): ?string
    {
        return $this->address;
    }

    /**
     * The limit on each lookup, in milliseconds.
     */
    public function timeoutMs(): int
    {
        return $this->timeoutMs;
    }

    /**
     * Make one lookup and read its answer.
     *
     * @param string $url
     *   The rendered URL.
     * @param string $type
     *   The record type asked for.
     */
    private function lookup(string $url, string $type): LookupResult
    {
        $response = $this->fetch($url);

        if (is_string($response)) {
            return LookupResult::unknown($response);
        }

        return $this->responseReader->read($response['status'], $response['body'], $type);
    }

    /**
     * The `CURLOPT_RESOLVE` entry pinning the endpoint's host to `address`.
     *
     * @return list<string>
     *   One entry, or none when no address is pinned.
     */
    protected function resolveEntries(): array
    {
        if ($this->address === null) {
            return [];
        }

        $address = str_contains($this->address, ':') ? '[' . $this->address . ']' : $this->address;

        return [sprintf('%s:%d:%s', $this->endpointTemplate->host(), $this->endpointTemplate->port(), $address)];
    }

    /**
     * Whether curl can be used.
     *
     * @codeCoverageIgnore
     *   Answered by the environment, and every supported one has curl.
     */
    protected static function curlAvailable(): bool
    {
        return function_exists('curl_init');
    }

    /**
     * Make the request, as a seam so tests need no network.
     *
     * @param string $url
     *   The rendered URL.
     *
     * @return array{status: int, body: string}|string
     *   The status and body, or why there is none.
     *
     * @codeCoverageIgnore
     *   The one place the network is touched. Everything it returns is read by code the
     *   tests cover through this seam.
     */
    protected function fetch(string $url): array|string
    {
        if (!self::$curlHandle instanceof \CurlHandle) {
            $handle = curl_init();

            if ($handle === false) {
                return 'curl could not be initialised';
            }

            self::$curlHandle = $handle;
        } else {
            curl_reset(self::$curlHandle);
        }

        $body = '';
        $tooLarge = false;

        curl_setopt_array(self::$curlHandle, [
            CURLOPT_URL => $url,
            CURLOPT_HTTPGET => true,
            CURLOPT_HTTPHEADER => $this->headers,
            CURLOPT_RESOLVE => $this->resolveEntries(),
            CURLOPT_TIMEOUT_MS => $this->timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $this->timeoutMs,
            // Without it, a limit under a second fails at once on builds whose resolver
            // uses signals.
            CURLOPT_NOSIGNAL => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$tooLarge): int {
                if (strlen($body) + strlen($chunk) > ResponseReader::MAX_BODY_BYTES) {
                    $tooLarge = true;

                    // Fewer bytes than offered aborts the transfer.
                    return 0;
                }

                $body .= $chunk;

                return strlen($chunk);
            },
        ]);

        $ok = curl_exec(self::$curlHandle);

        if ($tooLarge) {
            return 'the response is larger than ' . ResponseReader::MAX_BODY_BYTES . ' bytes';
        }

        if ($ok === false) {
            return 'request failed: ' . curl_error(self::$curlHandle);
        }

        return ['status' => curl_getinfo(self::$curlHandle, CURLINFO_RESPONSE_CODE), 'body' => $body];
    }
}
