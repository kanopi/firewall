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
use Kanopi\Firewall\Utility\Path;

/**
 * One declared `metadata.sources` entry, validated.
 *
 * A definition is inert — it says where a list lives, how to decode it, and
 * what to do when it cannot be read. `SourceLoader` is what acts on it.
 */
final class SourceDefinition
{
    /**
     * Decode a source body into records before selection.
     */
    public const FORMATS = ['txt', 'json', 'ndjson', 'yaml', 'csv', 'tsv'];

    /**
     * Decompress a source body before decoding it.
     */
    public const COMPRESSIONS = ['none', 'gzip'];

    /**
     * What to do when a source cannot be fetched or decoded.
     *
     * - `last_known_good`: reuse the last cached entries; empty if there are none.
     * - `fail_open`: contribute nothing and carry on.
     * - `abort`: throw, taking the whole firewall bootstrap with it.
     */
    public const ERROR_POLICIES = ['last_known_good', 'fail_open', 'abort'];

    /**
     * Entry shapes a source can assert its output conforms to.
     */
    public const VALIDATORS = ['cidr', 'ip', 'regex', 'string'];

    /**
     * @param string $name
     *   Identifier used in logs, errors, and match attribution.
     * @param string $upstream
     *   Absolute path, relative path, or URL the list is read from.
     * @param string $format
     *   One of self::FORMATS.
     * @param string $compression
     *   One of self::COMPRESSIONS.
     * @param string|null $select
     *   Dot-path selecting the records to keep. Null keeps the decoded root.
     * @param array<int, mixed> $where
     *   Conditional-logic rules every kept record must satisfy.
     * @param string|array<array-key, mixed>|null $template
     *   Output shape. Null passes records through untouched.
     * @param string|null $validate
     *   One of self::VALIDATORS, asserted per entry.
     * @param float|null $maxDelta
     *   Reject a refresh moving the entry count by more than this fraction.
     * @param int|null $ttl
     *   Seconds before a cached fetch is revalidated. Null uses the global default.
     * @param string $onError
     *   One of self::ERROR_POLICIES.
     * @param bool $required
     *   When true, a failure aborts regardless of $onError.
     * @param bool $headers
     *   CSV/TSV only: treat the first row as column names.
     * @param string $comment
     *   Text formats only: strip from this marker to end of line.
     * @param string|null $delimiter
     *   CSV/TSV only: field delimiter. Null picks the format default.
     */
    public function __construct(
        public readonly string $name,
        public readonly string $upstream,
        public readonly string $format = 'txt',
        public readonly string $compression = 'none',
        public readonly ?string $select = null,
        public readonly array $where = [],
        public readonly string|array|null $template = null,
        public readonly ?string $validate = null,
        public readonly ?float $maxDelta = null,
        public readonly ?int $ttl = null,
        public readonly string $onError = 'last_known_good',
        public readonly bool $required = false,
        public readonly bool $headers = true,
        public readonly string $comment = '#',
        public readonly ?string $delimiter = null,
    ) {
    }

    /**
     * Build a definition from a declared array, validating as it goes.
     *
     * @param array<array-key, mixed> $declaration
     *   One entry from `metadata.sources`.
     * @param int $index
     *   Position in the list, used to name an unnamed source.
     *
     * @return self
     *   The validated definition.
     *
     * @throws SourceException
     *   When a required key is missing or a value is not one of the allowed set.
     */
    public static function fromArray(array $declaration, int $index = 0): self
    {
        $upstream = $declaration['upstream'] ?? null;

        if (!is_string($upstream) || trim($upstream) === '') {
            throw new SourceException(
                sprintf('Source at index %d is missing a non-empty "upstream".', $index)
            );
        }

        $name = $declaration['name'] ?? null;
        $name = is_string($name) && trim($name) !== '' ? trim($name) : self::deriveName($upstream, $index);

        $format = self::choice($declaration, 'format', self::FORMATS, self::inferFormat($upstream), $name);
        $compression = self::choice(
            $declaration,
            'compression',
            self::COMPRESSIONS,
            self::inferCompression($upstream),
            $name
        );
        $onError = self::choice($declaration, 'on_error', self::ERROR_POLICIES, 'last_known_good', $name);

        $validate = $declaration['validate'] ?? null;
        if ($validate !== null) {
            $validate = self::choice($declaration, 'validate', self::VALIDATORS, 'string', $name);
        }

        $template = $declaration['template'] ?? null;
        if ($template !== null && !is_string($template) && !is_array($template)) {
            throw new SourceException(
                sprintf('Source "%s": "template" must be a string or a map, %s given.', $name, gettype($template))
            );
        }

        $where = $declaration['where'] ?? [];
        if (!is_array($where)) {
            throw new SourceException(
                sprintf('Source "%s": "where" must be a list of rules, %s given.', $name, gettype($where))
            );
        }

        $maxDelta = $declaration['max_delta'] ?? null;
        if ($maxDelta !== null) {
            if (!is_numeric($maxDelta) || (float) $maxDelta < 0) {
                throw new SourceException(
                    sprintf('Source "%s": "max_delta" must be a non-negative number.', $name)
                );
            }

            $maxDelta = (float) $maxDelta;
        }

        $ttl = $declaration['ttl'] ?? null;
        if ($ttl !== null) {
            if (!is_numeric($ttl) || (int) $ttl < 0) {
                throw new SourceException(
                    sprintf('Source "%s": "ttl" must be a non-negative integer.', $name)
                );
            }

            $ttl = (int) $ttl;
        }

        $select = $declaration['select'] ?? null;
        if ($select !== null && !is_string($select)) {
            throw new SourceException(
                sprintf('Source "%s": "select" must be a string dot-path.', $name)
            );
        }

        return new self(
            name: $name,
            upstream: trim($upstream),
            format: $format,
            compression: $compression,
            select: $select,
            where: array_values($where),
            template: $template,
            validate: $validate,
            maxDelta: $maxDelta,
            ttl: $ttl,
            onError: $onError,
            required: (bool) ($declaration['required'] ?? false),
            headers: (bool) ($declaration['headers'] ?? true),
            comment: is_string($declaration['comment'] ?? null) ? $declaration['comment'] : '#',
            delimiter: is_string($declaration['delimiter'] ?? null) ? $declaration['delimiter'] : null,
        );
    }

    /**
     * Whether the upstream is remote rather than a local file.
     *
     * @return bool
     *   True when the upstream is a URL.
     */
    public function isRemote(): bool
    {
        return Path::looksLikeUrl($this->upstream);
    }

    /**
     * A failure on this source must abort rather than degrade.
     *
     * @return bool
     *   True when the source is required or its policy is `abort`.
     */
    public function mustAbortOnError(): bool
    {
        return $this->required || $this->onError === 'abort';
    }

    /**
     * A stable identity for cache entries belonging to this source.
     *
     * Keyed on the upstream and every option that changes the decoded result,
     * so editing a `select` or `template` invalidates the cache without the
     * upstream having to change.
     *
     * @return string
     *   A hex digest.
     */
    public function fingerprint(): string
    {
        return hash('sha256', serialize([
            $this->upstream,
            $this->format,
            $this->compression,
            $this->select,
            $this->where,
            $this->template,
            $this->validate,
            $this->headers,
            $this->comment,
            $this->delimiter,
        ]));
    }

    /**
     * Read an enumerated option, falling back when it is absent.
     *
     * @param array<array-key, mixed> $declaration
     *   The raw declaration.
     * @param string $key
     *   Option being read.
     * @param array<int, string> $allowed
     *   Permitted values.
     * @param string $default
     *   Used when the key is absent.
     * @param string $name
     *   Source name, for the error message.
     *
     * @return string
     *   The chosen value.
     *
     * @throws SourceException
     *   When the declared value is not in $allowed.
     */
    private static function choice(array $declaration, string $key, array $allowed, string $default, string $name): string
    {
        $value = $declaration[$key] ?? null;

        if ($value === null) {
            return $default;
        }

        if (!is_string($value) || !in_array($value, $allowed, true)) {
            throw new SourceException(sprintf(
                'Source "%s": "%s" must be one of %s, got %s.',
                $name,
                $key,
                implode(', ', $allowed),
                is_string($value) ? sprintf('"%s"', $value) : gettype($value)
            ));
        }

        return $value;
    }

    /**
     * Guess a format from the upstream's extension.
     *
     * Only used when `format` is not declared. `txt` is the fallback because
     * newline-delimited is what most published lists actually are.
     *
     * @param string $upstream
     *   The declared upstream.
     *
     * @return string
     *   One of self::FORMATS.
     */
    private static function inferFormat(string $upstream): string
    {
        $path = parse_url($upstream, PHP_URL_PATH);
        $path = is_string($path) ? $path : $upstream;

        // Look past a compression suffix: "ranges.json.gz" is JSON.
        $path = preg_replace('/\.(gz|gzip)$/i', '', $path) ?? $path;

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return match ($extension) {
            'json' => 'json',
            'ndjson', 'jsonl' => 'ndjson',
            'yaml', 'yml' => 'yaml',
            'csv' => 'csv',
            'tsv' => 'tsv',
            default => 'txt',
        };
    }

    /**
     * Guess compression from the upstream's extension.
     *
     * @param string $upstream
     *   The declared upstream.
     *
     * @return string
     *   One of self::COMPRESSIONS.
     */
    private static function inferCompression(string $upstream): string
    {
        $path = parse_url($upstream, PHP_URL_PATH);
        $path = is_string($path) ? $path : $upstream;

        return preg_match('/\.(gz|gzip)$/i', $path) === 1 ? 'gzip' : 'none';
    }

    /**
     * Derive a readable name from the upstream when none was declared.
     *
     * @param string $upstream
     *   The declared upstream.
     * @param int $index
     *   Position in the source list.
     *
     * @return string
     *   A name for logs and errors.
     */
    private static function deriveName(string $upstream, int $index): string
    {
        $path = parse_url($upstream, PHP_URL_PATH);
        $path = is_string($path) ? $path : $upstream;

        $base = pathinfo($path, PATHINFO_FILENAME);

        return $base !== '' ? $base : 'source-' . $index;
    }
}
