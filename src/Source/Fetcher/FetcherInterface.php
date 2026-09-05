<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source\Fetcher;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\FetchResult;
use Kanopi\Firewall\Source\SourceDefinition;

/**
 * Retrieves a source body, revalidating rather than re-downloading when it can.
 */
interface FetcherInterface
{
    /**
     * Whether this fetcher handles a source's upstream.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source.
     *
     * @return bool
     *   True when this fetcher can retrieve it.
     */
    public function supports(SourceDefinition $sourceDefinition): bool;

    /**
     * Retrieve the body, or confirm the cached copy is still current.
     *
     * @param SourceDefinition $sourceDefinition
     *   The source to fetch.
     * @param array<string, mixed> $validators
     *   Cache validators from the previous fetch: `etag`, `last_modified`.
     *
     * @return FetchResult
     *   The body, or a not-modified result.
     *
     * @throws SourceException
     *   When the upstream cannot be read.
     */
    public function fetch(SourceDefinition $sourceDefinition, array $validators = []): FetchResult;
}
