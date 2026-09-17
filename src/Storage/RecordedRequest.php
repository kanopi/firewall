<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Storage;

use Symfony\Component\HttpFoundation\Request;

/**
 * What a block record keeps about the request that caused it (#375).
 *
 * Before this, the answer was *everything*: the whole cookie jar and the whole
 * header set, verbatim. So a visitor who was blocked had their session cookie,
 * their `Authorization` header and their challenge pass persisted into the
 * firewall's store — and `bin/firewall-block --show --json` printed them back.
 *
 * Three things made that worse than it first reads. The block list is the
 * artifact operators *share* — pasted into a ticket, read over a call, and with
 * `SharedStorage` replicated across a fleet. A record outlives the request by
 * design, for the ban's duration, which for an escalating ban is days. And none
 * of those credentials are the firewall's to hold: the session cookie belongs to
 * the application in front of it.
 *
 * ## An allowlist, not a denylist
 *
 * A denylist is a promise to have thought of every header name a framework might
 * invent — `X-Session`, `X-Auth`, `X-Vendor-Token`, the next one. An allowlist is
 * wrong in the direction that loses evidence rather than the one that keeps
 * credentials, and evidence is recoverable by configuration.
 *
 * ```yaml
 * storage:
 *   config:
 *     record_request:
 *       cookies: []                                      # default: none
 *       headers: [user-agent, referer, accept-language]   # default: a short list
 *       query: ["*"]                                      # default: everything
 *       body: []                                          # default: none
 * ```
 *
 * `["*"]` keeps everything in that bucket, for a deployment that has decided it
 * wants the forensics and understood what that means.
 *
 * ## Why the four defaults are not the same
 *
 * They reflect where the risk actually is rather than a wish to look consistent.
 *
 * - **Cookies: none.** This is the session-cookie problem, and it is unambiguous.
 * - **Headers: a short list.** `Cookie`, `Authorization` and every `X-*-Token` are
 *   the hazard; `User-Agent` and `Referer` are most of the forensic value.
 * - **Query: everything.** For the commonest case — a scanner — the query string
 *   *is* the attack, and redacting it by default would gut the record for the
 *   thing it is most often read about. The risk is real but narrower: a password
 *   reset link, an API key somebody put in a URL.
 * - **Body: none.** A blocked login attempt has the password in it.
 */
final class RecordedRequest
{
    /**
     * Keeps everything in a bucket.
     */
    public const EVERYTHING = '*';

    /**
     * Headers kept when nothing says otherwise.
     *
     * Chosen as the ones that describe the *client* rather than authenticate it.
     * Nothing here can be replayed to become somebody.
     *
     * @var array<int, string>
     */
    public const DEFAULT_HEADERS = [
        'user-agent',
        'referer',
        'accept',
        'accept-language',
        'accept-encoding',
        'content-type',
        'content-length',
        'host',
        'origin',
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-real-ip',
        'cf-connecting-ip',
        'true-client-ip',
    ];

    /**
     * @param array<int, string>|null $cookies
     *   Cookie names to keep, or NULL for everything.
     * @param array<int, string>|null $headers
     *   Header names to keep, lowercased, or NULL for everything.
     * @param array<int, string>|null $query
     *   Query parameter names to keep, or NULL for everything.
     * @param array<int, string>|null $body
     *   Request body field names to keep, or NULL for everything.
     */
    private function __construct(
        private readonly ?array $cookies,
        private readonly ?array $headers,
        private readonly ?array $query,
        private readonly ?array $body,
    ) {
    }

    /**
     * Read the policy from a storage backend's configuration.
     *
     * A malformed `record_request` falls back to the defaults rather than
     * throwing. Storage is constructed on the request path, and the failure mode
     * of a strict read here is a site that does not start because somebody typed
     * a list where a map goes — while the failure mode of a lenient one is a
     * record that keeps *less* than intended, which is the safe direction and is
     * visible in the very next record anybody looks at.
     *
     * @param mixed $declared
     *   The `record_request` value, or NULL when none is configured.
     *
     * @return self
     *   The policy.
     */
    public static function fromConfig(mixed $declared): self
    {
        $declared = is_array($declared) ? $declared : [];

        return new self(
            self::names($declared, 'cookies', []),
            self::names($declared, 'headers', self::DEFAULT_HEADERS, true),
            self::names($declared, 'query', null),
            self::names($declared, 'body', []),
        );
    }

    /**
     * Everything, as the firewall recorded it before this existed.
     *
     * For a caller assembling storage by hand that wants the old behaviour, and
     * for the tests that pin what the old behaviour was.
     *
     * @return self
     *   A policy that keeps every field.
     */
    public static function everything(): self
    {
        return new self(null, null, null, null);
    }

    /**
     * The parts of a request worth keeping.
     *
     * @param Request $request
     *   The request being recorded.
     *
     * @return array<string, mixed>
     *   The record.
     */
    public function serialize(Request $request): array
    {
        $query = $this->filter($request->query->all(), $this->query);

        return [
            'method' => $request->getMethod(),
            // Rebuilt from what survived, not taken from the request. `getUri()`
            // carries the query string, so narrowing `query` while copying the
            // original URI would be a setting that silently does nothing — a
            // password reset token redacted out of one field and left in the
            // one beside it.
            'uri' => $this->uri($request, $query),
            'path' => $request->getPathInfo(),
            'query' => $query,
            'request' => $this->filter($request->request->all(), $this->body),
            'headers' => $this->filter($this->headerNames($request), $this->headers),
            'cookies' => $this->filter($request->cookies->all(), $this->cookies),
        ];
    }

    /**
     * Whether this policy keeps everything, as the firewall used to.
     *
     * `firewall-doctor` asks, so an operator who has opted back in is told they
     * have rather than left to infer it from an absence.
     *
     * @return bool
     *   TRUE when no bucket is narrowed.
     */
    public function keepsEverything(): bool
    {
        return $this->cookies === null
            && $this->headers === null
            && $this->query === null
            && $this->body === null;
    }

    /**
     * The URI, with any query parameters the policy dropped removed from it.
     *
     * @param Request $request
     *   The request being recorded.
     * @param array<string, mixed> $query
     *   The query parameters that survived.
     *
     * @return string
     *   The URI.
     */
    private function uri(Request $request, array $query): string
    {
        if ($this->query === null || $request->query->all() === $query) {
            return $request->getUri();
        }

        $base = $request->getSchemeAndHttpHost() . $request->getBaseUrl() . $request->getPathInfo();

        return $query === [] ? $base : $base . '?' . http_build_query($query);
    }

    /**
     * Header values, keyed by lowercase name.
     *
     * Symfony hands back a list per header, which is faithful and awkward to
     * read in a record. A single value is unwrapped; a genuinely repeated header
     * keeps its list rather than quietly losing everything after the first.
     *
     * @param Request $request
     *   The request being recorded.
     *
     * @return array<string, mixed>
     *   Header name to value.
     */
    private function headerNames(Request $request): array
    {
        $headers = [];

        foreach ($request->headers->all() as $name => $values) {
            $headers[strtolower((string) $name)] = count($values) === 1 ? $values[0] : $values;
        }

        return $headers;
    }

    /**
     * Keep the entries an allowlist permits.
     *
     * @param array<array-key, mixed> $values
     *   Everything available.
     * @param array<int, string>|null $allowed
     *   Names to keep, or NULL to keep all of them.
     *
     * @return array<string, mixed>
     *   What survived.
     */
    private function filter(array $values, ?array $allowed): array
    {
        $kept = [];

        foreach ($values as $name => $value) {
            $name = (string) $name;

            if ($allowed === null || in_array($name, $allowed, true)) {
                $kept[$name] = $value;
            }
        }

        return $kept;
    }

    /**
     * Read one bucket's allowlist.
     *
     * @param array<array-key, mixed> $declared
     *   The `record_request` map.
     * @param string $key
     *   The bucket.
     * @param array<int, string>|null $default
     *   Used when the bucket is absent. NULL means everything.
     * @param bool $lowercase
     *   Whether names are matched case-insensitively, which headers are and
     *   cookies, query parameters and body fields are not — those are the
     *   application's own names, and `Token` and `token` are two of them.
     *
     * @return array<int, string>|null
     *   Names to keep, or NULL for everything.
     */
    private static function names(array $declared, string $key, ?array $default, bool $lowercase = false): ?array
    {
        if (!array_key_exists($key, $declared)) {
            return $default;
        }

        $value = $declared[$key];

        // A bare string is the shorthand somebody will write for one name, and
        // `headers: "*"` is the shorthand for the wildcard. Both are obvious
        // enough to accept rather than refuse.
        if (is_string($value)) {
            $value = [$value];
        }

        if (!is_array($value)) {
            return $default;
        }

        $names = [];

        foreach ($value as $name) {
            if (!is_string($name)) {
                continue;
            }

            if ($name === self::EVERYTHING) {
                return null;
            }

            $names[] = $lowercase ? strtolower(trim($name)) : trim($name);
        }

        return $names;
    }
}
