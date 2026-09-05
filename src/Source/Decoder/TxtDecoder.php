<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source\Decoder;

use Kanopi\Firewall\Source\SourceDefinition;

/**
 * Newline-delimited text, which is what most published lists actually are.
 *
 * Real lists are rarely clean: they carry `#` banners, blank separators,
 * trailing whitespace, and trailing labels like `1.2.3.4 # scanner`. Handling
 * that here rather than making every consumer do it is the point.
 */
final class TxtDecoder implements DecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array
    {
        $lines = preg_split('/\R/', $body);

        if ($lines === false) {
            return [];
        }

        $records = [];

        foreach ($lines as $line) {
            $line = $this->stripComment($line, $sourceDefinition->comment);
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            $records[] = $line;
        }

        return $records;
    }

    /**
     * Remove a comment from a line.
     *
     * A marker only opens a comment at the start of the line or after
     * whitespace, so a value that legitimately contains the marker — a URL
     * fragment, say — survives.
     *
     * @param string $line
     *   The raw line.
     * @param string $marker
     *   Comment marker, empty to disable comment stripping.
     *
     * @return string
     *   The line up to the comment.
     */
    private function stripComment(string $line, string $marker): string
    {
        if ($marker === '') {
            return $line;
        }

        if (str_starts_with(ltrim($line), $marker)) {
            return '';
        }

        $position = 0;

        while (($position = strpos($line, $marker, $position)) !== false) {
            if ($position > 0 && preg_match('/\s/', $line[$position - 1]) === 1) {
                return substr($line, 0, $position);
            }

            $position += strlen($marker);
        }

        return $line;
    }
}
