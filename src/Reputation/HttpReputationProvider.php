<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\ReputationUnavailableException;
use Kanopi\Firewall\Source\Decoder\DecoderRegistry;
use Kanopi\Firewall\Source\SourceAuth;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceUpstream;
use Kanopi\Firewall\Utility\DotPath;

/**
 * Any endpoint that scores an address, without writing PHP (#204).
 *
 * ```yaml
 * config:
 *   provider: http
 *   upstream:
 *     url: "https://reputation.example.com/v1/score?ip={ip}"
 *     auth:
 *       type: bearer
 *       token: "%env(REPUTATION_TOKEN)%"
 *   score_path: data.score
 *   threshold: 75
 * ```
 *
 * ## Every part of it is somebody else's vocabulary
 *
 * - **`upstream:`** is `SourceUpstream` -- the same block a rule source declares
 *   since #161, so `method`, `headers`, `body`, `auth`, `timeout`,
 *   `max_redirects` and `allow_insecure` all work here because they already
 *   worked there. That includes the refusal to send a credential over plain
 *   http, which this would otherwise have had to remember to write.
 * - **`format:`** is the decoder registry: `json`, `txt`, `csv`, `tsv`,
 *   `ndjson`, `yaml`, `xml`. Decoding is the only stage that knows about wire
 *   formats; everything after it is a plain array.
 * - **`score_path:`** is `DotPath`, the syntax a source's `select:` uses.
 *
 * Somebody who has configured a rule source has already learned all three, and
 * none of them got a second implementation to drift from the first.
 *
 * ## The URL, or the body, has to name the address
 *
 * A request that does not carry `{ip}` anywhere asks the same question for
 * every visitor, which is a reputation check that can neither fail nor help. It
 * is refused at construction rather than discovered from a log line saying
 * every address scores 4.
 *
 * ## What it does about scores it cannot find
 *
 * A response with no score where one was declared is a **failure**, not a zero.
 * An endpoint that changed its shape, or that returns `{"error": ...}` with a
 * 200, would otherwise read as "every address is clean" -- protection silently
 * switched off, with a healthy-looking service behind it.
 */
class HttpReputationProvider implements SubjectAwareReputationProviderInterface
{
    /**
     * How long a verdict stays cached, in seconds.
     *
     * An hour rather than AbuseIPDB's day: a service somebody runs themselves
     * is usually free to call and more likely to be updating its own data.
     */
    protected const DEFAULT_CACHE_TTL = 3600;

    /**
     * How long a failed lookup stays cached, in seconds.
     */
    protected const DEFAULT_ERROR_CACHE_TTL = 300;

    /**
     * Seconds to wait on the endpoint before giving up.
     */
    protected const DEFAULT_TIMEOUT = 2.0;

    /**
     * The token replaced with the subject being asked about.
     *
     * `{ip}` is the same token under its 2.27.0 name, kept because a
     * configuration written against that release should not need editing to
     * keep working -- and because for a rule that scores addresses it is still
     * the more readable of the two.
     */
    protected const TOKENS = ['{subject}', '{ip}'];

    /**
     * The endpoint, as a rule source would declare it.
     */
    protected SourceUpstream $upstream;

    /**
     * Enough of a source to hand the decoders, which take one for messages.
     */
    protected SourceDefinition $sourceDefinition;

    /**
     * @param array<int|string, mixed> $config
     *   The rule's `config:` block.
     *
     * @throws ConfigurationException
     *   When the endpoint cannot be read, does not name the address, or
     *   declares no way of finding a score. All of them are startup failures
     *   rather than runtime ones: a reputation rule that cannot call anything,
     *   or cannot read what comes back, is not a rule -- and discovering that
     *   from a warning on every request is how it goes unnoticed.
     */
    public function __construct(protected array $config = [])
    {
        $declaration = $this->config['upstream'] ?? null;

        if ($declaration === null) {
            throw new ConfigurationException(
                'A reputation rule using the `http` provider needs an `upstream`: a URL string, or the '
                . 'same map of request options a rule source takes. The URL or body must contain `{ip}`, '
                . 'where the client address goes.'
            );
        }

        // SourceException, rethrown as the configuration failure it is here. A
        // rule source degrades when its upstream is wrong because it has a last
        // known good copy to fall back on; a reputation rule has nothing.
        try {
            $this->upstream = SourceUpstream::fromDeclaration($declaration, $this->getName());
        } catch (\Throwable $throwable) {
            throw new ConfigurationException($throwable->getMessage(), 0, $throwable);
        }

        if (!$this->mentionsSubject()) {
            throw new ConfigurationException(sprintf(
                'The reputation upstream never mentions `%s`, so it would ask the same question for every '
                . 'visitor: %s',
                self::TOKENS[0],
                SourceAuth::redactUrl($this->upstream->url)
            ));
        }

        if ($this->scorePath() === '' && $this->scorePattern() === null) {
            throw new ConfigurationException(
                'A reputation rule using the `http` provider needs either a `score_path` -- where the score '
                . 'is in the decoded response, in the dot syntax a source `select:` uses -- or a '
                . '`score_pattern`, a regular expression with one capturing group, read straight from the '
                . 'body.'
            );
        }

        $this->sourceDefinition = new SourceDefinition($this->getName(), $this->upstream, $this->format());

        // Fails here rather than per request, and names the formats rather than
        // leaving somebody to guess which spelling of `yml` this one wanted.
        try {
            (new DecoderRegistry())->get($this->format());
        } catch (\Throwable $throwable) {
            throw new ConfigurationException($throwable->getMessage(), 0, $throwable);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        $name = $this->config['provider_name'] ?? null;

        return is_string($name) && trim($name) !== '' ? trim($name) : 'Reputation service';
    }

    /**
     * {@inheritdoc}
     *
     * Derived from the endpoint's host, so two services configured on one site
     * do not read each other's cached verdicts -- their scores are on different
     * scales and mean different things.
     */
    public function getSlug(): string
    {
        $host = (string) (parse_url($this->upstream->url, PHP_URL_HOST) ?: 'endpoint');

        return 'http-' . preg_replace('/[^a-z0-9]+/', '-', strtolower($host));
    }

    /**
     * {@inheritdoc}
     *
     * Always ready: everything it needs is checked at construction, where
     * getting it wrong is a startup failure rather than a silent no-op.
     */
    public function getConfigurationProblem(): ?string
    {
        return null;
    }

    /**
     * {@inheritdoc}
     *
     * Public addresses only by default, as a third-party service would want.
     * `public_only: false` is for a service on your own network, which may be
     * the only thing that knows anything about `10.0.0.4`.
     */
    public function knowsAbout(string $ip): bool
    {
        return $this->knowsAboutSubject(new ReputationSubject($ip));
    }

    /**
     * {@inheritdoc}
     *
     * Any kind. A rule pointed at an endpoint that scores email addresses is
     * the operator saying the endpoint scores email addresses, and this
     * provider has no way to know better -- unlike `AbuseIpdbProvider`, which
     * knows exactly what AbuseIPDB scores and says so by not implementing this
     * interface at all.
     */
    public function handles(ReputationSubject $reputationSubject): bool
    {
        return true;
    }

    /**
     * Whether a particular value is worth a call.
     *
     * Only addresses are filtered. There is no equivalent of "not publicly
     * routable" for an email address, and inventing one -- a syntax check, a
     * disposable-domain list -- would be this library making a judgement the
     * service it is about to ask exists to make.
     *
     * @param ReputationSubject $reputationSubject
     *   The subject to look up.
     *
     * @return bool
     *   TRUE when the lookup is worth making.
     */
    protected function knowsAboutSubject(ReputationSubject $reputationSubject): bool
    {
        if (!$reputationSubject->isAddress()) {
            return true;
        }

        if (($this->config['public_only'] ?? true) === false) {
            return filter_var($reputationSubject->value, FILTER_VALIDATE_IP) !== false;
        }

        return filter_var(
            $reputationSubject->value,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultCacheTtl(): int
    {
        return self::DEFAULT_CACHE_TTL;
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultErrorCacheTtl(): int
    {
        return self::DEFAULT_ERROR_CACHE_TTL;
    }

    /**
     * {@inheritdoc}
     */
    public function check(string $ip): ReputationVerdict
    {
        return $this->checkSubject(new ReputationSubject($ip));
    }

    /**
     * {@inheritdoc}
     */
    public function checkSubject(ReputationSubject $reputationSubject): ReputationVerdict
    {
        $body = $this->request($reputationSubject);
        $score = $this->extract($body, $this->scorePattern(), $this->scorePath());

        if (!is_numeric($score)) {
            // Not a zero. An endpoint that changed shape would otherwise read
            // as "every address is clean", which is protection switched off
            // with a healthy service behind it.
            throw new ReputationUnavailableException(sprintf(
                'the reputation service returned no score at %s',
                $this->scorePattern() ?? '`' . $this->scorePath() . '`'
            ));
        }

        return new ReputationVerdict((float) $score, $this->trusted($body), ['score' => (float) $score]);
    }

    /**
     * Ask the endpoint about one subject.
     *
     * @param ReputationSubject $reputationSubject
     *   What to substitute into the request.
     *
     * @return string
     *   The response body.
     *
     * @throws ReputationUnavailableException
     *   When the endpoint cannot be reached or does not answer with a 200.
     */
    protected function request(ReputationSubject $reputationSubject): string
    {
        $url = str_replace(self::TOKENS, rawurlencode($reputationSubject->value), $this->upstream->requestUrl());
        $headers = ['Accept: application/json'];

        foreach ($this->upstream->requestHeaders() as $name => $value) {
            $headers[] = $name . ': ' . $value;
        }

        $options = [
            'method' => $this->upstream->method,
            'timeout' => $this->upstream->timeout ?? ProviderConfig::float(
                $this->config,
                'timeout',
                self::DEFAULT_TIMEOUT,
                $this->getName()
            ),
            'ignore_errors' => true,
            'max_redirects' => $this->upstream->maxRedirects,
            'header' => $headers,
        ];

        if ($this->upstream->body !== null) {
            // Substituted in the body too, which is the whole point of POST
            // support: `{"ip": "{ip}"}`. Encoded as JSON rather than for a URL,
            // since that is what a body of this shape is.
            $options['content'] = str_replace(
                self::TOKENS,
                trim((string) json_encode($reputationSubject->value), '"'),
                $this->upstream->body
            );
            $options['header'][] = 'Content-Type: ' . $this->contentType();
        }

        $handle = @fopen($url, 'r', false, stream_context_create(['http' => $options]));

        if ($handle === false) {
            // Redacted, because a `query` credential is in this URL and this
            // message reaches a log line.
            throw new ReputationUnavailableException(sprintf(
                'could not reach %s',
                SourceAuth::redactUrl($this->upstream->url)
            ));
        }

        $metadata = stream_get_meta_data($handle);
        $body = stream_get_contents($handle);
        fclose($handle);

        /** @var array<int, string> $headerLines */
        $headerLines = is_array($metadata['wrapper_data'] ?? null) ? $metadata['wrapper_data'] : [];
        $status = HttpStatus::fromHeaders($headerLines);

        if ($status !== 200) {
            throw new ReputationUnavailableException($this->describeStatus($status), $status);
        }

        if ($body === false || $body === '') {
            throw new ReputationUnavailableException('the reputation service returned an empty body', $status);
        }

        return $body;
    }

    /**
     * Pull one value out of a response.
     *
     * Two ways, and never both at once: a pattern reads the **raw body**, and a
     * path reads the **decoded structure**. Keeping them exclusive is what stops
     * `format:` from having to mean something for a regular expression.
     *
     * @param string $body
     *   The response body.
     * @param string|null $pattern
     *   A regular expression with one capturing group, or NULL.
     * @param string $path
     *   A dot path into the decoded body, or an empty string.
     *
     * @return mixed
     *   What was found, or NULL.
     *
     * @throws ReputationUnavailableException
     *   When the body cannot be decoded at all.
     */
    protected function extract(string $body, ?string $pattern, string $path): mixed
    {
        if ($pattern !== null) {
            // A pattern that blows the backtrack limit returns FALSE here,
            // which lands in "no value" and fails open. That is the right
            // outcome and it is free, so there is nothing to guard.
            return preg_match($pattern, $body, $matches) === 1 ? ($matches[1] ?? null) : null;
        }

        // No guard for an empty path: construction refuses a rule that declares
        // neither a path nor a pattern, so reaching here without a pattern
        // means there is a path.
        return DotPath::first($this->decode($body), $path);
    }

    /**
     * Turn the response body into an array, in whatever format it arrived.
     *
     * @param string $body
     *   The response body.
     *
     * @return array<array-key, mixed>
     *   The decoded structure.
     *
     * @throws ReputationUnavailableException
     *   When the body is not the format the rule declared.
     */
    protected function decode(string $body): array
    {
        try {
            return (new DecoderRegistry())->get($this->format())->decode($body, $this->sourceDefinition);
        } catch (\Throwable $throwable) {
            throw new ReputationUnavailableException(sprintf(
                'the reputation service returned a body that is not %s — %s',
                $this->format(),
                $throwable->getMessage()
            ));
        }
    }

    /**
     * Whether the response vouches for the address.
     *
     * @param string $body
     *   The response body.
     *
     * @return bool
     *   TRUE when a trusted path or pattern is configured and finds something
     *   true. One that finds nothing is FALSE rather than a failure: "this
     *   response does not say the address is trusted" is a complete answer,
     *   where a missing score is not.
     */
    protected function trusted(string $body): bool
    {
        $pattern = $this->pattern('trusted_pattern');
        $path = $this->config['trusted_path'] ?? null;
        $path = is_string($path) ? trim($path) : '';

        if ($pattern === null && $path === '') {
            return false;
        }

        $value = $this->extract($body, $pattern, $path);

        // Strings, because JSON written by hand says "true" and "yes" as often
        // as it says true, and reading either as FALSE would quietly stop an
        // allow list working. A pattern that matched at all is also a yes,
        // which is what `/"allowlisted":\s*true/` means.
        if (is_string($value)) {
            return $value !== '' && !in_array(strtolower(trim($value)), ['0', 'false', 'no'], true);
        }

        return (bool) $value;
    }

    /**
     * Turn an HTTP status into something an operator can act on.
     *
     * @param int|null $status
     *   The status code, or NULL when none could be parsed.
     *
     * @return string
     *   What to write in the log line.
     */
    protected function describeStatus(?int $status): string
    {
        return match ($status) {
            401, 403 => 'the reputation service rejected the credentials',
            404 => 'the reputation service does not know that endpoint',
            429 => 'the reputation service is rate limiting this firewall',
            null => 'the reputation service returned no parseable status',
            default => 'the reputation service returned HTTP ' . $status,
        };
    }

    /**
     * Whether the request names the subject anywhere.
     *
     * The URL or the body -- a POST carrying the subject in its body needs no
     * token in its query string, and requiring one there would mean putting an
     * email address in an access log to satisfy a check.
     *
     * @return bool
     *   TRUE when a token appears in either.
     */
    protected function mentionsSubject(): bool
    {
        $written = $this->upstream->url . $this->upstream->body;

        foreach (self::TOKENS as $token) {
            if (str_contains($written, $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The declared response format.
     *
     * @return string
     *   A decoder name, `json` unless something else is declared.
     */
    protected function format(): string
    {
        $format = $this->config['format'] ?? null;

        return is_string($format) && trim($format) !== '' ? strtolower(trim($format)) : 'json';
    }

    /**
     * Where the score is in the decoded response.
     *
     * @return string
     *   A dot path, or an empty string when there is none.
     */
    protected function scorePath(): string
    {
        $path = $this->config['score_path'] ?? null;

        return is_string($path) ? trim($path) : '';
    }

    /**
     * The pattern the score is read with, when it is read from raw text.
     *
     * @return string|null
     *   The expression, or NULL when none is configured.
     */
    protected function scorePattern(): ?string
    {
        return $this->pattern('score_pattern');
    }

    /**
     * Read and validate one configured regular expression.
     *
     * Compiled here, at construction time, rather than on a request: an
     * unusable pattern is a rule that can never produce a verdict, and saying
     * so once at startup is the difference between a fixed config and a warning
     * nobody reads repeating forever.
     *
     * @param string $key
     *   The config key holding it.
     *
     * @return string|null
     *   The expression, or NULL when the key is unset.
     *
     * @throws ConfigurationException
     *   When it does not compile, or captures nothing.
     */
    protected function pattern(string $key): ?string
    {
        $pattern = $this->config[$key] ?? null;

        if (!is_string($pattern) || trim($pattern) === '') {
            return null;
        }

        $pattern = trim($pattern);

        if (@preg_match($pattern, '') === false) {
            throw new ConfigurationException(sprintf(
                'The reputation `%s` is not a usable regular expression: %s. It needs delimiters, like '
                . '`/risk=(\\d+)/`.',
                $key,
                $pattern
            ));
        }

        // A pattern with nothing to capture can only ever answer "it matched",
        // and a score needs a value. Counting groups is cheaper than finding
        // out from a rule that never scores anything.
        if ((int) preg_match_all('/\((?!\?)/', (string) preg_replace('/\\\\\(/', '', $pattern)) === 0) {
            throw new ConfigurationException(sprintf(
                'The reputation `%s` has no capturing group, so there is nothing for it to read: %s. '
                . 'Put the part you want in parentheses, like `/risk=(\\d+)/`.',
                $key,
                $pattern
            ));
        }

        return $pattern;
    }

    /**
     * The content type a declared body is sent with.
     *
     * @return string
     *   The configured type, or JSON, which is what a scoring API takes.
     */
    protected function contentType(): string
    {
        $type = $this->config['content_type'] ?? null;

        return is_string($type) && trim($type) !== '' ? trim($type) : 'application/json';
    }
}
