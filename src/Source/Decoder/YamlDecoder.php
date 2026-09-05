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
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * A single YAML document.
 *
 * Worth knowing: YAML happily parses a newline-delimited IP list into one
 * folded scalar rather than a list, which is why a `.txt` list declared as
 * `format: yaml` produces nothing useful. The non-array guard below turns that
 * into an error instead of a silent empty result.
 */
final class YamlDecoder implements DecoderInterface
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
            $decoded = Yaml::parse($body);
        } catch (ParseException $parseException) {
            throw new SourceException(
                sprintf('Source "%s": body is not valid YAML — %s', $sourceDefinition->name, $parseException->getMessage()),
                0,
                $parseException
            );
        }

        if (!is_array($decoded)) {
            throw new SourceException(sprintf(
                'Source "%s": YAML decoded to %s, expected a sequence or mapping. A newline-delimited '
                . 'list parses as a single scalar — declare it as format: txt.',
                $sourceDefinition->name,
                gettype($decoded)
            ));
        }

        return $decoded;
    }
}
