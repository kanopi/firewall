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
     * Read a file's contents.
     *
     * A seam. The readability checks above can pass and the read still fail —
     * the file is unlinked or its permissions change in between — which is a
     * real race but not one a test can provoke in-process. Overriding this is
     * how that path gets exercised.
     *
     * @param string $path
     *   File to read.
     *
     * @return string|false
     *   The contents, or FALSE when the read failed.
     */
    protected function readFile(string $path): string|false
    {
        return @file_get_contents($path);
    }

    /**
     * {@inheritdoc}
     */
    public function fetch(SourceDefinition $sourceDefinition, array $validators = []): FetchResult
    {
        $path = $sourceDefinition->upstream->url;

        if (!is_file($path) || !is_readable($path)) {
            throw new SourceException(sprintf(
                'Source "%s": cannot read "%s".',
                $sourceDefinition->name,
                $path
            ));
        }

        // Before the read, not after. A local file is the one upstream whose
        // size can be known without paying for it, so a list that has grown
        // past the ceiling costs a stat rather than a four-gigabyte string
        // (#366). A `false` from filesize() -- a race, or a path the stat
        // cache disagrees about -- falls through to the read rather than
        // failing the source over a number it could not get.
        $limit = $sourceDefinition->upstream->maxSize;
        $size = $limit > 0 ? @filesize($path) : false;

        if (is_int($size) && $size > $limit) {
            throw new SourceException(sprintf(
                'Source "%s": "%s" is %d bytes, more than upstream.max_size allows (%d). Refusing '
                . 'it rather than using part of a list.',
                $sourceDefinition->name,
                $path,
                $size,
                $limit
            ));
        }

        $body = $this->readFile($path);

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
