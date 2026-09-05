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
 * Turns a fetched body into a PHP structure.
 *
 * Decoding is the only stage that knows about wire formats. Everything after
 * it — select, where, template, validate — works on plain arrays, which is
 * what lets one pipeline serve every format.
 */
interface DecoderInterface
{
    /**
     * Decode a body.
     *
     * @param string $body
     *   The decompressed source body.
     * @param SourceDefinition $sourceDefinition
     *   The source being decoded, for format-specific options.
     *
     * @return array<array-key, mixed>
     *   The decoded structure. Text formats return a list of lines; structured
     *   formats return whatever the document contained.
     *
     * @throws SourceException
     *   When the body cannot be decoded.
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array;
}
