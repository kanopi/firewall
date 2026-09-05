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

/**
 * Maps a declared `format` to the decoder that handles it.
 *
 * Decoders are created once and reused; they hold no per-source state.
 */
final class DecoderRegistry
{
    /**
     * Decoders by format name.
     *
     * @var array<string, DecoderInterface>
     */
    private array $decoders = [];

    /**
     * @param array<string, DecoderInterface> $decoders
     *   Overrides, keyed by format. Anything not supplied uses the built-in.
     */
    public function __construct(array $decoders = [])
    {
        $csvDecoder = new CsvDecoder();

        $this->decoders = $decoders + [
            'txt' => new TxtDecoder(),
            'json' => new JsonDecoder(),
            'ndjson' => new NdjsonDecoder(),
            'yaml' => new YamlDecoder(),
            'csv' => $csvDecoder,
            'tsv' => $csvDecoder,
        ];
    }

    /**
     * Fetch the decoder for a format.
     *
     * @param string $format
     *   A declared format.
     *
     * @return DecoderInterface
     *   The decoder.
     *
     * @throws SourceException
     *   When no decoder is registered for the format.
     */
    public function get(string $format): DecoderInterface
    {
        if (!isset($this->decoders[$format])) {
            throw new SourceException(sprintf(
                'No decoder registered for format "%s"; known formats are %s.',
                $format,
                implode(', ', array_keys($this->decoders))
            ));
        }

        return $this->decoders[$format];
    }
}
