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
 * Delimiter-separated rows, serving both `csv` and `tsv`.
 *
 * With `header_row: true` each row decodes to a map keyed by column name, so a
 * template reaches fields as `{value[asn]}`. With `header_row: false` rows stay
 * numerically indexed and fields are `{value[0]}`.
 */
final class CsvDecoder implements DecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array
    {
        $delimiter = $sourceDefinition->delimiter ?? ($sourceDefinition->format === 'tsv' ? "\t" : ',');
        // `preg_split` with a literal, valid pattern has no failure mode, so
        // there is no branch to take here — just a default for the analyser.
        $lines = preg_split('/\R/', $body) ?: [];

        $rows = [];

        foreach ($lines as $line) {
            if (trim($line) === '') {
                continue;
            }

            // A comment marker only counts at the start of a row here; inside a
            // field it is data, and str_getcsv is what decides field boundaries.
            if ($sourceDefinition->comment !== '' && str_starts_with(ltrim($line), $sourceDefinition->comment)) {
                continue;
            }

            $rows[] = str_getcsv($line, $delimiter, '"', '\\');
        }

        if ($rows === []) {
            return [];
        }

        if (!$sourceDefinition->headerRow) {
            return $rows;
        }

        $columns = array_map(static fn (mixed $column): string => trim((string) $column), array_shift($rows));
        $records = [];

        foreach ($rows as $row) {
            $record = [];

            foreach ($columns as $index => $column) {
                if ($column === '') {
                    continue;
                }

                $record[$column] = $row[$index] ?? null;
            }

            $records[] = $record;
        }

        return $records;
    }
}
