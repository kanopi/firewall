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
 * XML, as the plain array everything downstream works on.
 *
 * The document is converted rather than traversed, so `select:` and
 * `score_path:` address it with the same dot syntax as JSON or YAML and nothing
 * after this stage knows which format it came from.
 *
 * Attributes land under `@attributes`, which is SimpleXML's convention and the
 * reason a path into an XML document often reads
 * `Response.@attributes.score` rather than `Response.score`. Keeping SimpleXML's
 * shape is deliberate: inventing a flatter one would mean a path that matches
 * no documentation anybody else has written about their own API.
 *
 * ## A document type declaration is refused outright
 *
 * An XML body is bytes somebody else's server produced, and every well-known
 * way of weaponising one starts with a `<!DOCTYPE>`: an entity pointing at
 * `file:///etc/passwd` or an internal URL, which is a file read and an SSRF out
 * of a response body (XXE), or nested entities that expand to gigabytes
 * (billion laughs). Turning entity substitution off stops the first and not
 * reliably the second, and leaves the parser doing work on a declaration
 * nothing legitimate needs.
 *
 * So a body containing a DOCTYPE is rejected before the parser sees it, and
 * `LIBXML_NONET` plus the absence of `LIBXML_NOENT` stay as defence in depth.
 * No scoring API or address list sends a DOCTYPE; anything that does is worth
 * a clear error rather than a best effort.
 *
 * Depth is libxml's own: it refuses a document nested deeper than 256 elements,
 * so a nesting bomb is a parse failure rather than a stack this has to guard.
 *
 * This is why XML is not simply another line in the decoder registry: it is the
 * one format where parsing untrusted bytes is itself the risk.
 */
final class XmlDecoder implements DecoderInterface
{
    /**
     * {@inheritdoc}
     */
    public function decode(string $body, SourceDefinition $sourceDefinition): array
    {
        if (trim($body) === '') {
            throw new SourceException(sprintf('Source "%s": body is empty, so there is no XML to read.', $sourceDefinition->name));
        }

        // Before the parser, not by configuring it: the check is what makes the
        // guarantee simple enough to state.
        if (preg_match('/<!DOCTYPE/i', $body) === 1) {
            throw new SourceException(sprintf(
                'Source "%s": refusing an XML body with a DOCTYPE declaration. It is how external '
                . 'entity and entity expansion attacks are delivered, and nothing that publishes a '
                . 'list or a score needs one.',
                $sourceDefinition->name
            ));
        }

        // Collected rather than emitted: a malformed body is reported through
        // the exception below, and libxml's own warnings would otherwise reach
        // the host application's error handler.
        $previous = libxml_use_internal_errors(true);

        try {
            // LIBXML_NONET refuses to fetch anything over the network, and no
            // LIBXML_NOENT means declared entities are never substituted.
            // Together they are the XXE defence; neither is a default.
            $document = simplexml_load_string($body, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOCDATA);

            if ($document === false) {
                $error = libxml_get_last_error();

                throw new SourceException(sprintf(
                    'Source "%s": body is not valid XML — %s',
                    $sourceDefinition->name,
                    $error === false ? 'the parser rejected it' : trim($error->message)
                ));
            }

            // Encoding is not checked, because the parser above has already
            // rejected everything that could make it fail: libxml refuses a
            // document nested deeper than 256 elements ("Excessive depth in
            // document") and refuses byte sequences that are not valid UTF-8.
            // A branch for a failure that cannot arrive is a claim about
            // behaviour that nothing verifies.
            $decoded = json_decode((string) json_encode($document), true);

            return is_array($decoded) ? $decoded : [];
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }
}
