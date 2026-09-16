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
use Kanopi\Firewall\Logging\LoggingTrait;
use Kanopi\Firewall\Source\Decoder\DecoderRegistry;
use Kanopi\Firewall\Source\Fetcher\FetcherInterface;
use Kanopi\Firewall\Source\Fetcher\HttpFetcher;
use Kanopi\Firewall\Source\Fetcher\LocalFetcher;
use Kanopi\Firewall\Utility\DotPath;

/**
 * Runs one source through the pipeline and hands back its entries.
 *
 * ```
 * fetch → decompress → decode → select → where → template → validate
 * ```
 *
 * Every format collapses to a PHP array at `decode`, which is what lets one
 * pipeline serve text, JSON, NDJSON, YAML, CSV, and TSV without any stage after
 * the decoder knowing which it was.
 */
final class SourceLoader
{
    use LoggingTrait;

    /**
     * Fetchers tried in order.
     *
     * @var array<int, FetcherInterface>
     */
    private array $fetchers;

    /**
     * Whether remote fetching is suppressed for this loader.
     */
    private readonly bool $offline;

    /**
     * @param SourceCache|null $sourceCache
     *   Where results are stored, or NULL for the default location.
     * @param DecoderRegistry|null $decoderRegistry
     *   Format handlers, or NULL for the built-in set.
     * @param TemplateRenderer|null $templateRenderer
     *   Entry renderer, or NULL for the default.
     * @param RecordFilter|null $recordFilter
     *   `where` evaluator, or NULL for the default.
     * @param EntryValidator|null $entryValidator
     *   Entry validator, or NULL for the default.
     * @param SourceVerifier|null $sourceVerifier
     *   Checksum/signature verifier, or NULL for the default.
     * @param array<int, FetcherInterface>|null $fetchers
     *   Fetchers to try, or NULL for local plus HTTP.
     * @param bool|null $offline
     *   When true, never touch the network: cached entries are used and a
     *   source with no cache is an error. This is the mode a request path
     *   should run in, with refreshes done out of band by `bin/firewall-sources`.
     *   NULL takes the KANOPI_FIREWALL_SOURCES_OFFLINE constant, defaulting to
     *   false.
     */
    public function __construct(
        private readonly ?SourceCache $sourceCache = null,
        private readonly ?DecoderRegistry $decoderRegistry = null,
        private readonly ?TemplateRenderer $templateRenderer = null,
        private readonly ?RecordFilter $recordFilter = null,
        private readonly ?EntryValidator $entryValidator = null,
        ?array $fetchers = null,
        ?bool $offline = null,
        private readonly ?SourceVerifier $sourceVerifier = null,
    ) {
        $this->fetchers = $fetchers ?? [new LocalFetcher(), new HttpFetcher()];
        $this->offline = $offline ?? (defined('KANOPI_FIREWALL_SOURCES_OFFLINE') && (bool) constant('KANOPI_FIREWALL_SOURCES_OFFLINE'));
    }

    /**
     * Load one source's entries.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source to load.
     * @param bool $force
     *   Skip the freshness check and revalidate now. Used by the sync command.
     *
     * @return array<int, mixed>
     *   The entries this source contributes.
     *
     * @throws SourceException
     *   When the source cannot be fetched, decoded, or validated.
     */
    public function load(SourceDefinition $sourceDefinition, bool $force = false): array
    {
        $cache = $this->cache();
        $meta = $cache->meta($sourceDefinition);
        $cached = $cache->entries($sourceDefinition);

        if (!$force && $cached !== null && $cache->isFresh($sourceDefinition, $meta)) {
            $this->getLogger()->debug('Source served from cache', [
                'source' => $sourceDefinition->name,
                'entries' => count($cached),
            ]);

            return $cached;
        }

        if ($this->offline && $sourceDefinition->isRemote()) {
            if ($cached !== null) {
                return $cached;
            }

            throw new SourceException(sprintf(
                'Source "%s": running offline with nothing cached. Sync sources before serving requests.',
                $sourceDefinition->name
            ));
        }

        $fetchResult = $this->fetcher($sourceDefinition)->fetch($sourceDefinition, [
            'etag' => $meta['etag'] ?? null,
            'last_modified' => $meta['last_modified'] ?? null,
        ]);

        if ($fetchResult->notModified && $cached !== null) {
            // Upstream confirmed our copy; restamp so the TTL restarts without
            // re-running the pipeline.
            $cache->store($sourceDefinition, $cached, [
                'etag' => $fetchResult->etag,
                'last_modified' => $fetchResult->lastModified,
                'body_hash' => $meta['body_hash'] ?? null,
            ]);

            return $cached;
        }

        $body = $fetchResult->body;

        if ($body === null) {
            throw new SourceException(sprintf(
                'Source "%s": upstream reported no change but nothing is cached.',
                $sourceDefinition->name
            ));
        }

        // Before the body-hash short-circuit below, not after. That hash
        // compares this fetch against the previous one; it is a cache
        // fingerprint and has never said anything about authenticity. Checking
        // first also means a source given a `checksum:` after its cache was
        // warmed gets verified on the next refresh rather than on the next
        // change (#365).
        $this->verify($sourceDefinition, $body);

        $hash = hash('sha256', $body);

        if ($cached !== null && ($meta['body_hash'] ?? null) === $hash) {
            // Byte-identical to what produced the cached entries. The upstream
            // does not do conditional requests, but we can still skip decoding.
            $cache->store($sourceDefinition, $cached, [
                'etag' => $fetchResult->etag,
                'last_modified' => $fetchResult->lastModified,
                'body_hash' => $hash,
            ]);

            return $cached;
        }

        $entries = $this->pipeline($sourceDefinition, $body);

        $this->validator()->assertDelta(
            count($entries),
            isset($meta['entry_count']) ? (int) $meta['entry_count'] : null,
            $sourceDefinition->maxDelta,
            $sourceDefinition->name
        );

        $cache->store($sourceDefinition, $entries, [
            'etag' => $fetchResult->etag,
            'last_modified' => $fetchResult->lastModified,
            'body_hash' => $hash,
        ]);

        $this->getLogger()->debug('Source loaded', [
            'source' => $sourceDefinition->name,
            'upstream' => $sourceDefinition->displayUpstream(),
            'entries' => count($entries),
        ]);

        return $entries;
    }

    /**
     * Check a fetched body against what the source asserts about it.
     *
     * Runs on the raw body, before decompression: a digest is published over
     * the artifact as it is distributed, so `ranges.json.gz` is hashed gzipped.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     * @param string $body
     *   The fetched bytes.
     *
     * @throws SourceException
     *   When the body does not verify, or the sidecar cannot be fetched.
     *   `SourceManager` turns that into this source's `on_error` policy, which
     *   is what keeps the last known good copy rather than taking the bytes.
     */
    private function verify(SourceDefinition $sourceDefinition, string $body): void
    {
        $verification = $sourceDefinition->verification;

        if (!$verification instanceof SourceVerification) {
            return;
        }

        $sidecar = $verification->needsSidecar()
            ? $this->fetchSidecar($sourceDefinition, $verification)
            : null;

        $this->verifier()->assert(
            $verification,
            $body,
            $sidecar,
            $sourceDefinition->name,
            $sourceDefinition->fileName()
        );

        $this->getLogger()->debug('Source body verified', [
            'source' => $sourceDefinition->name,
            'verification' => $verification->describe(),
        ]);
    }

    /**
     * Fetch the sidecar that carries the assertion.
     *
     * Goes through the same fetcher the list does, so a local file's checksum
     * is read from disk and a private feed's is fetched with the same
     * credential.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     * @param SourceVerification $sourceVerification
     *   What it asserts, for the sidecar's location.
     *
     * @return string
     *   The sidecar body.
     *
     * @throws SourceException
     *   When the sidecar cannot be read, or comes back empty.
     */
    private function fetchSidecar(SourceDefinition $sourceDefinition, SourceVerification $sourceVerification): string
    {
        // A definition rather than a bare URL, because the fetchers take one
        // and because `supports()` has to pick local-vs-HTTP for the sidecar
        // the same way it did for the list. Conditional validators are
        // deliberately not passed: a 304 here would leave nothing to compare
        // against, and a sidecar is a few dozen bytes.
        $sidecarDefinition = new SourceDefinition(
            name: $sourceDefinition->name . ' (' . $sourceVerification->describe() . ')',
            upstream: $sourceDefinition->upstream->sidecar($sourceVerification->url ?? ''),
        );

        $body = $this->fetcher($sidecarDefinition)->fetch($sidecarDefinition)->body;

        if ($body === null || $body === '') {
            throw new SourceException(sprintf(
                'Source "%s": the %s sidecar at %s came back empty, so the body cannot be checked.',
                $sourceDefinition->name,
                $sourceVerification->algorithm,
                $sidecarDefinition->displayUpstream()
            ));
        }

        return $body;
    }

    /**
     * The body verifier, built on first use.
     *
     * @return SourceVerifier
     *   The verifier.
     */
    private function verifier(): SourceVerifier
    {
        return $this->sourceVerifier ?? new SourceVerifier();
    }

    /**
     * Turn a fetched body into entries.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     * @param string $body
     *   The fetched bytes.
     *
     * @return array<int, mixed>
     *   The rendered, validated entries.
     *
     * @throws SourceException
     *   When decompression or decoding fails.
     */
    public function pipeline(SourceDefinition $sourceDefinition, string $body): array
    {
        $decoded = $this->decoders()
            ->get($sourceDefinition->format)
            ->decode($this->decompress($sourceDefinition, $body), $sourceDefinition);

        $records = $this->select($sourceDefinition, $decoded);
        $records = $this->filter()->filter($records, $sourceDefinition->where);

        $renderer = $this->renderer();
        $entries = [];
        $dropped = 0;

        foreach ($records as $record) {
            $entry = $renderer->render($record, $sourceDefinition->template);

            if ($entry === null) {
                $dropped++;
                continue;
            }

            $entries[] = $entry;
        }

        if ($dropped > 0) {
            $this->getLogger()->warning('Source records dropped: template placeholders did not resolve', [
                'source' => $sourceDefinition->name,
                'dropped' => $dropped,
                'kept' => count($entries),
            ]);
        }

        // Two questions, asked separately: is the entry well formed, and would
        // it match everybody. `0.0.0.0/0` passes the first and fails the
        // second (#364).
        $entries = $this->validator()->refuseCatchAll(
            $entries,
            $sourceDefinition->name,
            $sourceDefinition->allowCatchAll
        );

        return $this->validator()->filter($entries, $sourceDefinition->validate, $sourceDefinition->name);
    }

    /**
     * Narrow a decoded document to the records a source wants.
     *
     * With no `select`, a decoded list is already the record set and anything
     * else is treated as a single record — so a source whose document *is* the
     * list needs no selector at all.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     * @param array<array-key, mixed> $decoded
     *   The decoded document.
     *
     * @return array<int, mixed>
     *   The selected records.
     */
    private function select(SourceDefinition $sourceDefinition, array $decoded): array
    {
        if ($sourceDefinition->select === null || trim($sourceDefinition->select) === '') {
            return array_is_list($decoded) ? $decoded : [$decoded];
        }

        return DotPath::values($decoded, $sourceDefinition->select);
    }

    /**
     * Decompress a body when the source declares compression.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     * @param string $body
     *   The fetched bytes.
     *
     * @return string
     *   The decompressed body.
     *
     * @throws SourceException
     *   When the body is not valid for the declared compression.
     */
    private function decompress(SourceDefinition $sourceDefinition, string $body): string
    {
        if ($sourceDefinition->compression !== 'gzip') {
            return $body;
        }

        if (!$this->gzipAvailable()) {
            throw new SourceException(sprintf(
                'Source "%s": declares gzip compression but ext-zlib is not available.',
                $sourceDefinition->name
            ));
        }

        $decoded = @gzdecode($body);

        if ($decoded === false) {
            throw new SourceException(sprintf(
                'Source "%s": body is not valid gzip data.',
                $sourceDefinition->name
            ));
        }

        return $decoded;
    }

    /**
     * Whether this host can decompress gzip.
     *
     * A seam, for the same reason `LocalFetcher::readFile()` is one: ext-zlib
     * is either compiled in or it is not, and a test cannot take it away.
     *
     * @return bool
     *   TRUE when gzdecode() is available.
     */
    protected function gzipAvailable(): bool
    {
        return function_exists('gzdecode');
    }

    /**
     * Pick the fetcher handling a source's upstream.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source being loaded.
     *
     * @return FetcherInterface
     *   The first fetcher that supports it.
     *
     * @throws SourceException
     *   When nothing can fetch the upstream.
     */
    private function fetcher(SourceDefinition $sourceDefinition): FetcherInterface
    {
        foreach ($this->fetchers as $fetcher) {
            if ($fetcher->supports($sourceDefinition)) {
                return $fetcher;
            }
        }

        throw new SourceException(sprintf(
            'Source "%s": no fetcher handles "%s".',
            $sourceDefinition->name,
            $sourceDefinition->displayUpstream()
        ));
    }

    /**
     * The cache, built on first use.
     *
     * @return SourceCache
     *   The result cache.
     */
    private function cache(): SourceCache
    {
        return $this->sourceCache ?? new SourceCache();
    }

    /**
     * The decoder registry, built on first use.
     *
     * @return DecoderRegistry
     *   The registry.
     */
    private function decoders(): DecoderRegistry
    {
        return $this->decoderRegistry ?? new DecoderRegistry();
    }

    /**
     * The template renderer, built on first use.
     *
     * @return TemplateRenderer
     *   The renderer.
     */
    private function renderer(): TemplateRenderer
    {
        return $this->templateRenderer ?? new TemplateRenderer();
    }

    /**
     * The record filter, built on first use.
     *
     * @return RecordFilter
     *   The filter.
     */
    private function filter(): RecordFilter
    {
        return $this->recordFilter ?? new RecordFilter();
    }

    /**
     * The entry validator, built on first use.
     *
     * @return EntryValidator
     *   The validator.
     */
    private function validator(): EntryValidator
    {
        return $this->entryValidator ?? new EntryValidator();
    }
}
