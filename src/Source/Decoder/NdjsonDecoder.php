<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source\Decoder;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceDefinition;

/**
 * Newline-delimited JSON, one document per line.
 *
 * Distinct from `json` because the body as a whole is not valid JSON — several
 * threat feeds publish this shape.
 */
final class NdjsonDecoder implements DecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array
    {
        // `preg_split` with a literal, valid pattern has no failure mode, so
        // there is no branch to take here — just a default for the analyser.
        $lines = preg_split('/\R/', $body) ?: [];

        $records = [];

        foreach ($lines as $number => $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            try {
                $records[] = json_decode($line, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            } catch (\JsonException $jsonException) {
                throw new SourceException(sprintf(
                    'Source "%s": line %d is not valid JSON — %s',
                    $sourceDefinition->name,
                    $number + 1,
                    $jsonException->getMessage()
                ), 0, $jsonException);
            }
        }

        return $records;
    }
}
