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
use Kanopi\Firewall\Source\RecordFilter;
use Kanopi\Firewall\Source\TemplateRenderer;
use Kanopi\Firewall\Utility\DotPath;

/**
 * Reads a DNS-over-HTTPS provider's answer, the way a Source reads a document.
 *
 * Every provider answers in its own shape, so how to pull the result out is configuration,
 * in the steps Sources already use -- `select`, `where`, `template` -- on the same classes,
 * so the path syntax and the filter operators are the ones `docs/configuration/sources.md`
 * documents (#473).
 *
 * Cloudflare's and Google's JSON APIs share one layout, which `dns-json` names:
 *
 * ```json
 * {"Status": 0, "Answer": [{"name": "1.66.249.66.in-addr.arpa", "type": 12, "data": "crawl-66-249-66-1.googlebot.com."}]}
 * ```
 *
 * **Every record, never just the first.** A forward lookup can answer with an alias (a
 * CNAME) before the address, and an address can have more than one PTR record. `type` keeps
 * the records of the type the lookup asked for -- supplied per lookup, so configuration never
 * spells it out -- whether the field holds a name or a number.
 *
 * Tolerant of what providers actually send, as measured on 2026-10-05: `Content-Type` is
 * never checked (`application/dns-json`, `application/json` and `application/x-javascript`
 * all occur), `Answer` may be missing or `null` when there is no record, and unknown fields
 * are ignored.
 */
final class ResponseReader
{
    /**
     * The layout Cloudflare's and Google's JSON APIs share.
     *
     * @var array<string, mixed>
     */
    public const DNS_JSON = [
        'format' => 'json',
        'status' => 'Status',
        'select' => 'Answer.*',
        'type' => 'type',
        'template' => '{value[data]}',
    ];

    /**
     * Named layouts `response:` may give instead of a map.
     *
     * @var array<string, array<string, mixed>>
     */
    public const SHORTHANDS = ['dns-json' => self::DNS_JSON];

    /**
     * The most of a body that is read. A DNS answer is a few hundred bytes.
     */
    public const MAX_BODY_BYTES = 65536;

    /**
     * The most records that are read from one answer.
     */
    public const MAX_RECORDS = 50;

    /**
     * Record type codes, for providers that report a number rather than a name.
     *
     * @var array<string, int>
     */
    private const TYPE_CODES = ['A' => 1, 'PTR' => 12, 'AAAA' => 28];

    /**
     * Keys a response map may have.
     *
     * @var list<string>
     */
    private const KEYS = ['format', 'status', 'select', 'where', 'type', 'template', 'none_http'];

    /**
     * Formats that can be read.
     *
     * @var list<string>
     */
    private const FORMATS = ['json'];

    /**
     * @param array<string, mixed> $layout
     *   A validated layout.
     */
    private function __construct(private readonly array $layout)
    {
    }

    /**
     * Build a reader from configuration.
     *
     * @param mixed $value
     *   `dns-json`, or a layout map. NULL means `dns-json`.
     *
     * @throws ConfigurationException
     *   Naming every problem with it.
     */
    public static function fromConfig(mixed $value): self
    {
        $problems = self::problems($value);

        if ($problems !== []) {
            throw new ConfigurationException('response: ' . implode('; ', $problems));
        }

        /** @var array<string, mixed> $layout */
        $layout = is_array($value) ? $value : self::SHORTHANDS[is_string($value) ? $value : 'dns-json'];

        return new self($layout);
    }

    /**
     * Everything wrong with a layout, without building it.
     *
     * @param mixed $value
     *   `dns-json`, a layout map, or NULL.
     *
     * @return list<string>
     *   Problems, empty when it can be used.
     */
    public static function problems(mixed $value): array
    {
        if ($value === null) {
            return [];
        }

        if (is_string($value)) {
            return isset(self::SHORTHANDS[$value])
                ? []
                : [sprintf('"%s" is not a known layout; the known one is %s, or give a map', $value, implode(', ', array_keys(self::SHORTHANDS)))];
        }

        if (!is_array($value)) {
            return [sprintf('must be a layout name or a map, not %s', get_debug_type($value))];
        }

        $problems = [];

        foreach (array_diff(array_map(strval(...), array_keys($value)), self::KEYS) as $unknown) {
            $problems[] = sprintf('unknown key "%s"; a layout takes %s', $unknown, implode(', ', self::KEYS));
        }

        $format = $value['format'] ?? null;

        if (!is_string($format) || $format === '') {
            $problems[] = 'format is required';
        } elseif (!in_array($format, self::FORMATS, true)) {
            $problems[] = $format === 'wire'
                ? 'format "wire" (RFC 8484 binary messages) is not supported yet; only json is'
                : sprintf('format "%s" is not supported; only json is', $format);
        }

        if (!is_string($value['template'] ?? null) || $value['template'] === '') {
            $problems[] = 'template is required, to say which field of each record holds the hostname or address';
        }

        foreach (['status', 'select', 'type'] as $path) {
            if (array_key_exists($path, $value) && (!is_string($value[$path]) || $value[$path] === '')) {
                $problems[] = sprintf('%s must be a path, as Sources write one', $path);
            }
        }

        if (array_key_exists('where', $value) && !is_array($value['where'])) {
            $problems[] = "where must be a list of rules, as a Source's where is";
        }

        if (array_key_exists('none_http', $value)) {
            $codes = $value['none_http'];

            if (!is_array($codes) || array_filter($codes, static fn(mixed $code): bool => !is_int($code) || $code < 100 || $code > 599) !== []) {
                $problems[] = 'none_http must be a list of HTTP status codes';
            }
        }

        return $problems;
    }

    /**
     * Read one answer.
     *
     * @param int $httpStatus
     *   The HTTP status code.
     * @param string $body
     *   The body.
     * @param string $type
     *   The record type the lookup asked for: `PTR`, `A` or `AAAA`.
     *
     * @return LookupResult
     *   What it says.
     */
    public function read(int $httpStatus, string $body, string $type): LookupResult
    {
        $noneHttp = is_array($this->layout['none_http'] ?? null) ? $this->layout['none_http'] : [];

        if (in_array($httpStatus, $noneHttp, true)) {
            return LookupResult::none();
        }

        if ($httpStatus !== 200) {
            return LookupResult::unknown(sprintf('HTTP %d', $httpStatus));
        }

        if (strlen($body) > self::MAX_BODY_BYTES) {
            return LookupResult::unknown('the response is larger than ' . self::MAX_BODY_BYTES . ' bytes');
        }

        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            return LookupResult::unknown('the response is not valid JSON');
        }

        if (!is_array($decoded)) {
            return LookupResult::unknown('the response is not a JSON object or list');
        }

        if (is_string($this->layout['status'] ?? null)) {
            $status = DotPath::first($decoded, $this->layout['status']);

            if (!is_int($status)) {
                return LookupResult::unknown('the response has no DNS status');
            }

            // NXDOMAIN: the name does not exist, which is an answer.
            if ($status === 3) {
                return LookupResult::none();
            }

            // SERVFAIL, REFUSED and the rest say nothing about the name.
            if ($status !== 0) {
                return LookupResult::unknown(sprintf('DNS status %d', $status));
            }
        }

        $records = is_string($this->layout['select'] ?? null)
            ? DotPath::values($decoded, $this->layout['select'])
            : (array_is_list($decoded) ? $decoded : [$decoded]);

        $records = array_slice($records, 0, self::MAX_RECORDS);

        if (is_array($this->layout['where'] ?? null) && $this->layout['where'] !== []) {
            $records = (new RecordFilter())->filter($records, $this->layout['where']);
        }

        if (is_string($this->layout['type'] ?? null)) {
            $field = $this->layout['type'];
            $records = array_filter(
                $records,
                static fn(mixed $record): bool => is_array($record) && self::isType(DotPath::first($record, $field), $type)
            );
        }

        $templateRenderer = new TemplateRenderer();
        $values = [];

        foreach ($records as $record) {
            $value = $templateRenderer->render($record, (string) $this->layout['template']);

            if (is_string($value)) {
                $values[] = $value;
            }
        }

        return LookupResult::answer($values);
    }

    /**
     * Whether a record's type field names the type asked for.
     *
     * @param mixed $actual
     *   The field's value: a name such as `PTR`, or a code such as `12`.
     * @param string $expected
     *   The type asked for.
     */
    private static function isType(mixed $actual, string $expected): bool
    {
        if (is_int($actual) || (is_string($actual) && ctype_digit($actual))) {
            return (int) $actual === (self::TYPE_CODES[$expected] ?? -1);
        }

        return is_string($actual) && strtoupper($actual) === $expected;
    }
}
