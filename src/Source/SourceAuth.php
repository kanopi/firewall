<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Exception\SourceException;

/**
 * Credentials for an upstream that is not public.
 *
 * Held as a value object rather than as raw headers so the credential has one
 * place to live and one place to be scrubbed. Everything that prints or logs an
 * upstream goes through `redactUrl()`, because a token in a query string
 * otherwise ends up in exception messages, debug logs, and CLI output.
 *
 * The secret itself is never rendered. `describe()` is what a log line gets.
 */
final class SourceAuth
{
    /**
     * Ways of presenting a credential.
     *
     * - `bearer`: `Authorization: Bearer <token>`
     * - `basic`: `Authorization: Basic base64(<username>:<password>)`
     * - `header`: an arbitrary `<name>: <value>` header
     * - `query`: an `<name>=<value>` parameter appended to the URL
     */
    public const TYPES = ['bearer', 'basic', 'header', 'query'];

    /**
     * Query parameters scrubbed from a URL before it is shown anywhere.
     *
     * Covers the configured `query` parameter and, beyond it, the names people
     * reach for when they paste a credential straight into an upstream URL
     * instead of declaring `auth`.
     *
     * @var array<int, string>
     */
    private const CREDENTIAL_PARAMETERS = [
        'token',
        'key',
        'apikey',
        'api_key',
        'access_token',
        'auth',
        'auth_token',
        'password',
        'passwd',
        'pwd',
        'secret',
        'signature',
        'sig',
    ];

    /**
     * @param string $type
     *   One of self::TYPES.
     * @param string|null $token
     *   Bearer token.
     * @param string|null $username
     *   Basic username.
     * @param string|null $password
     *   Basic password.
     * @param string|null $name
     *   Header or query parameter name.
     * @param string|null $value
     *   Header or query parameter value.
     */
    private function __construct(
        public readonly string $type,
        public readonly ?string $token = null,
        public readonly ?string $username = null,
        public readonly ?string $password = null,
        public readonly ?string $name = null,
        public readonly ?string $value = null,
    ) {
    }

    /**
     * Build credentials from a declared `auth` block.
     *
     * @param array<array-key, mixed> $declaration
     *   The `auth` map.
     * @param string $sourceName
     *   Source name, for error messages.
     *
     * @return self
     *   The validated credentials.
     *
     * @throws SourceException
     *   When the type is unknown or a required field is missing.
     */
    public static function fromArray(array $declaration, string $sourceName): self
    {
        $type = $declaration['type'] ?? null;

        if (!is_string($type) || !in_array($type, self::TYPES, true)) {
            throw new SourceException(sprintf(
                'Source "%s": auth.type must be one of %s, got %s.',
                $sourceName,
                implode(', ', self::TYPES),
                is_string($type) ? sprintf('"%s"', $type) : gettype($type)
            ));
        }

        return match ($type) {
            'bearer' => new self('bearer', token: self::required($declaration, 'token', $sourceName)),
            'basic' => new self(
                'basic',
                username: self::required($declaration, 'username', $sourceName),
                password: self::required($declaration, 'password', $sourceName)
            ),
            // Validated against self::TYPES above, so this is exhaustive.
            default => new self(
                $type,
                name: self::required($declaration, 'name', $sourceName),
                value: self::required($declaration, 'value', $sourceName)
            ),
        };
    }

    /**
     * Request headers carrying the credential.
     *
     * @return array<string, string>
     *   Header name to value; empty for query-parameter auth.
     */
    public function headers(): array
    {
        return match ($this->type) {
            'bearer' => ['Authorization' => 'Bearer ' . $this->token],
            'basic' => [
                'Authorization' => 'Basic ' . base64_encode(
                    $this->username . ':' . $this->password
                ),
            ],
            'header' => [(string) $this->name => (string) $this->value],
            default => [],
        };
    }

    /**
     * Apply query-parameter auth to a URL.
     *
     * @param string $url
     *   The upstream URL.
     *
     * @return string
     *   The URL, with the credential parameter appended when applicable.
     */
    public function applyToUrl(string $url): string
    {
        if ($this->type !== 'query') {
            return $url;
        }

        $separator = str_contains($url, '?') ? '&' : '?';

        return $url . $separator . rawurlencode((string) $this->name) . '=' . rawurlencode((string) $this->value);
    }

    /**
     * How this credential is presented, without presenting it.
     *
     * @return string
     *   A description safe to log.
     */
    public function describe(): string
    {
        return match ($this->type) {
            'header' => sprintf('header %s', (string) $this->name),
            'query' => sprintf('query %s', (string) $this->name),
            default => $this->type,
        };
    }

    /**
     * Strip anything credential-shaped from a URL so it can be shown.
     *
     * Handles both halves of the problem: `user:pass@host` userinfo, and query
     * parameters whose names suggest a secret. Applied to every upstream on its
     * way into a log line, an exception message, or CLI output — including
     * sources with no `auth` block, since a URL can carry a token on its own.
     *
     * @param string $url
     *   A URL, or a local path.
     *
     * @return string
     *   The URL with credentials replaced by `***`.
     */
    public static function redactUrl(string $url): string
    {
        $parts = parse_url($url);

        if ($parts === false || !isset($parts['host'])) {
            // Local paths and anything unparseable carry no credentials to
            // scrub, and rebuilding them would only mangle them.
            return $url;
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            $parts['user'] = '***';
            unset($parts['pass']);
        }

        if (isset($parts['query'])) {
            $parts['query'] = self::redactQuery($parts['query']);
        }

        return self::rebuild($parts);
    }

    /**
     * Replace credential-shaped parameter values in a query string.
     *
     * @param string $query
     *   The raw query string.
     *
     * @return string
     *   The query string with secrets replaced.
     */
    private static function redactQuery(string $query): string
    {
        $pairs = [];

        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }

            [$name] = array_pad(explode('=', $pair, 2), 2, '');

            $pairs[] = in_array(strtolower(rawurldecode($name)), self::CREDENTIAL_PARAMETERS, true)
                ? $name . '=***'
                : $pair;
        }

        return implode('&', $pairs);
    }

    /**
     * Reassemble a URL from its parsed parts.
     *
     * @param array<string, int|string> $parts
     *   Output of parse_url(), possibly modified.
     *
     * @return string
     *   The rebuilt URL.
     */
    private static function rebuild(array $parts): string
    {
        $url = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';

        if (isset($parts['user'])) {
            $url .= $parts['user'] . '@';
        }

        $url .= $parts['host'] ?? '';

        if (isset($parts['port'])) {
            $url .= ':' . $parts['port'];
        }

        $url .= $parts['path'] ?? '';

        if (isset($parts['query']) && $parts['query'] !== '') {
            $url .= '?' . $parts['query'];
        }

        if (isset($parts['fragment'])) {
            $url .= '#' . $parts['fragment'];
        }

        return $url;
    }

    /**
     * Read a required credential field.
     *
     * @param array<array-key, mixed> $declaration
     *   The `auth` map.
     * @param string $key
     *   Field being read.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @return string
     *   The field value.
     *
     * @throws SourceException
     *   When the field is missing or empty.
     */
    private static function required(array $declaration, string $key, string $sourceName): string
    {
        $value = $declaration[$key] ?? null;

        if (!is_string($value) || $value === '') {
            throw new SourceException(sprintf(
                'Source "%s": auth.%s is required for auth.type "%s".',
                $sourceName,
                $key,
                is_string($declaration['type'] ?? null) ? $declaration['type'] : '?'
            ));
        }

        return $value;
    }
}
