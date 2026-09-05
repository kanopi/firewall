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

/**
 * Loads every source declared on a plugin and merges their entries.
 *
 * Sources contribute in declaration order and a plugin's inline `config:` is
 * appended after all of them, so a local entry can always be added without
 * touching a shared list.
 *
 * **Failure is deliberately asymmetric.** A source that cannot be read is
 * logged and skipped, leaving the others intact — right for a block list, where
 * losing coverage beats losing the site. It is the wrong direction for an allow
 * list, where quietly dropping a CI provider's ranges means deploys start
 * getting blocked with only a log line to say why. Mark those sources
 * `required: true` (or `on_error: abort`) so a failure stops the bootstrap
 * instead of silently narrowing what is permitted.
 */
final class SourceManager
{
    use LoggingTrait;

    /**
     * Which source produced each merged entry, by entry index.
     *
     * @var array<int, string>
     */
    private array $provenance = [];

    /**
     * Failures recorded during the last load.
     *
     * @var array<int, array{source: string, message: string}>
     */
    private array $errors = [];

    /**
     * @param SourceLoader|null $sourceLoader
     *   Pipeline runner, or NULL for the default.
     * @param SourceCache|null $sourceCache
     *   Result cache, consulted for last-known-good fallbacks.
     */
    public function __construct(
        private readonly ?SourceLoader $sourceLoader = null,
        private readonly ?SourceCache $sourceCache = null,
    ) {
    }

    /**
     * Load and merge every declared source.
     *
     * @param array<int, mixed> $declarations
     *   Raw `metadata.sources` entries.
     * @param bool $force
     *   Revalidate rather than trusting a fresh cache.
     *
     * @return array<int, mixed>
     *   Merged entries, in declaration order.
     *
     * @throws SourceException
     *   When a source that must abort on error fails.
     */
    public function load(array $declarations, bool $force = false): array
    {
        $this->provenance = [];
        $this->errors = [];

        $entries = [];

        foreach ($this->definitions($declarations) as $sourceDefinition) {
            foreach ($this->loadOne($sourceDefinition, $force) as $entry) {
                $this->provenance[count($entries)] = $sourceDefinition->name;
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Build definitions from raw declarations.
     *
     * A malformed declaration is a configuration error, not a runtime one, so
     * it always throws — there is no sensible degraded behaviour for a source
     * nobody can interpret.
     *
     * @param array<int, mixed> $declarations
     *   Raw `metadata.sources` entries.
     *
     * @return array<int, SourceDefinition>
     *   The parsed definitions.
     *
     * @throws SourceException
     *   When a declaration is not a valid source.
     */
    public function definitions(array $declarations): array
    {
        $definitions = [];

        foreach (array_values($declarations) as $index => $declaration) {
            if (is_string($declaration)) {
                // Shorthand: a bare path or URL, decoded by extension.
                $declaration = ['upstream' => $declaration];
            }

            if (!is_array($declaration)) {
                throw new SourceException(sprintf(
                    'Source at index %d must be a map or a string, %s given.',
                    $index,
                    gettype($declaration)
                ));
            }

            $definitions[] = SourceDefinition::fromArray($declaration, $index);
        }

        return $definitions;
    }

    /**
     * Which source contributed each merged entry.
     *
     * Lets a match be attributed back to the list that caused it, rather than
     * reporting only that something matched.
     *
     * @return array<int, string>
     *   Source name by entry index.
     */
    public function provenance(): array
    {
        return $this->provenance;
    }

    /**
     * Failures from the last load.
     *
     * @return array<int, array{source: string, message: string}>
     *   One entry per source that could not be loaded.
     */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * Load one source, applying its failure policy.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source to load.
     * @param bool $force
     *   Revalidate rather than trusting a fresh cache.
     *
     * @return array<int, mixed>
     *   The source's entries, possibly from cache, possibly empty.
     *
     * @throws SourceException
     *   When the source must abort on error.
     */
    private function loadOne(SourceDefinition $sourceDefinition, bool $force): array
    {
        try {
            return $this->loader()->load($sourceDefinition, $force);
        } catch (SourceException $sourceException) {
            $this->errors[] = [
                'source' => $sourceDefinition->name,
                'message' => $sourceException->getMessage(),
            ];

            if ($sourceDefinition->mustAbortOnError()) {
                $this->getLogger()->error('Required source failed to load', [
                    'source' => $sourceDefinition->name,
                    'upstream' => $sourceDefinition->displayUpstream(),
                    'reason' => $sourceException->getMessage(),
                ]);

                throw $sourceException;
            }

            if ($sourceDefinition->onError === 'last_known_good') {
                $cached = $this->cache()->entries($sourceDefinition);

                if ($cached !== null) {
                    $this->getLogger()->error('Source failed to load; using last known good copy', [
                        'source' => $sourceDefinition->name,
                        'upstream' => $sourceDefinition->displayUpstream(),
                        'reason' => $sourceException->getMessage(),
                        'entries' => count($cached),
                    ]);

                    return $cached;
                }
            }

            $this->getLogger()->error('Source failed to load — its entries are NOT active', [
                'source' => $sourceDefinition->name,
                'upstream' => $sourceDefinition->displayUpstream(),
                'reason' => $sourceException->getMessage(),
                'on_error' => $sourceDefinition->onError,
            ]);

            return [];
        }
    }

    /**
     * The pipeline runner, built on first use.
     *
     * @return SourceLoader
     *   The loader.
     */
    private function loader(): SourceLoader
    {
        return $this->sourceLoader ?? new SourceLoader($this->sourceCache);
    }

    /**
     * The result cache, built on first use.
     *
     * @return SourceCache
     *   The cache.
     */
    private function cache(): SourceCache
    {
        return $this->sourceCache ?? new SourceCache();
    }
}
