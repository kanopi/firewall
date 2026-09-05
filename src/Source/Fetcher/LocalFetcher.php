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
 * Reads a source from the filesystem.
 *
 * This is the path a deployment should prefer: sync lists to disk out of band,
 * then let the runtime read local files and never touch the network while a
 * visitor waits.
 *
 * Unlike the HTTP fetcher this always reads the file and hands the body back,
 * leaving the loader's content hash to decide whether the pipeline needs to
 * run. Modification time and size would be cheaper, but they cannot tell apart
 * two edits made in the same second that leave the length unchanged — and a
 * local read costs far less than the decode it would wrongly skip.
 */
final class LocalFetcher implements FetcherInterface
{
    /**
     * {@inheritdoc}
     */
    public function supports(SourceDefinition $sourceDefinition): bool
    {
        return !$sourceDefinition->isRemote();
    }

    /**
     * {@inheritdoc}
     */
    public function fetch(SourceDefinition $sourceDefinition, array $validators = []): FetchResult
    {
        $path = $sourceDefinition->upstream;

        if (!is_file($path) || !is_readable($path)) {
            throw new SourceException(sprintf(
                'Source "%s": cannot read "%s".',
                $sourceDefinition->name,
                $path
            ));
        }

        $body = @file_get_contents($path);

        if ($body === false) {
            throw new SourceException(sprintf(
                'Source "%s": failed to read "%s".',
                $sourceDefinition->name,
                $path
            ));
        }

        return new FetchResult($body);
    }
}
