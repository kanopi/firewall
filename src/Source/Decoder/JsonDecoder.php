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
 * A single JSON document.
 */
final class JsonDecoder implements DecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array
    {
        if (trim($body) === '') {
            return [];
        }

        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException $jsonException) {
            throw new SourceException(
                sprintf('Source "%s": body is not valid JSON — %s', $sourceDefinition->name, $jsonException->getMessage()),
                0,
                $jsonException
            );
        }

        if (!is_array($decoded)) {
            throw new SourceException(sprintf(
                'Source "%s": JSON decoded to %s, expected an object or array.',
                $sourceDefinition->name,
                gettype($decoded)
            ));
        }

        return $decoded;
    }
}
