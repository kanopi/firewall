<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Source;

use Kanopi\Firewall\Exception\SourceException;

/**
 * What a source asserts about the bytes it fetches (#365).
 *
 * A rule source arrives over HTTPS and is used. HTTPS authenticates the *host*
 * and protects the transport; it says nothing about a repository that was
 * compromised, a CDN object that was replaced, or a publisher who pushed the
 * wrong file. This is the declaration that says what the bytes are supposed to
 * be, so the difference can be noticed.
 *
 * Two tiers, and the gap between them is the point:
 *
 * ```yaml
 * checksum: sha256                    # sidecar at <upstream>.sha256
 *
 * signature:                          # detached, key pinned in configuration
 *   algorithm: ed25519
 *   public_key: "%env(FIREWALL_FEED_KEY)%"
 * ```
 *
 * A sidecar fetched from the same host raises the bar without clearing it —
 * anyone who can replace the list can replace the sidecar. It is worth having
 * as the cheap tier, and it is exactly why a pinned-key signature is the one
 * that means something.
 *
 * Nothing here is required. Most published lists in this ecosystem ship no
 * sidecar at all, so a source that declares none keeps working unchanged;
 * `firewall-doctor` says how many are in that position rather than this
 * failing them.
 */
final class SourceVerification
{
    /**
     * Digest algorithms a `checksum:` may name.
     *
     * Deliberately not md5 or sha1. A checksum that a forger can collide is a
     * checksum that says nothing, and offering it would invite somebody to
     * match whatever their publisher happens to emit.
     */
    public const CHECKSUM_ALGORITHMS = ['sha256', 'sha384', 'sha512'];

    /**
     * Signature algorithms a `signature:` may name.
     */
    public const SIGNATURE_ALGORITHMS = ['ed25519'];

    public const CHECKSUM = 'checksum';

    public const SIGNATURE = 'signature';

    /**
     * @param string $mode
     *   self::CHECKSUM or self::SIGNATURE.
     * @param string $algorithm
     *   The named algorithm.
     * @param string|null $url
     *   Where the sidecar lives, or NULL when a digest is pinned inline.
     * @param string|null $value
     *   A digest pinned in configuration. Checksum mode only.
     * @param string|null $publicKey
     *   The publisher's public key. Signature mode only.
     */
    private function __construct(
        public readonly string $mode,
        public readonly string $algorithm,
        public readonly ?string $url = null,
        public readonly ?string $value = null,
        public readonly ?string $publicKey = null,
    ) {
    }

    /**
     * Read `checksum:` / `signature:` off a source declaration.
     *
     * @param array<array-key, mixed> $declaration
     *   One entry from `metadata.sources`.
     * @param string $sourceName
     *   Source name, for error messages.
     * @param string $upstreamUrl
     *   The list's own URL, used to derive a default sidecar location.
     *
     * @return self|null
     *   The declared verification, or NULL when the source declares none.
     *
     * @throws SourceException
     *   When the declaration is malformed, or declares both tiers at once.
     */
    public static function fromDeclaration(array $declaration, string $sourceName, string $upstreamUrl): ?self
    {
        $checksum = $declaration[self::CHECKSUM] ?? null;
        $signature = $declaration[self::SIGNATURE] ?? null;

        if ($checksum !== null && $signature !== null) {
            // Not merged, and not "signature wins". Two assertions about the
            // same bytes is a config somebody is midway through changing, and
            // guessing which half they meant is how the weaker one ends up
            // being the one that runs.
            throw new SourceException(sprintf(
                'Source "%s": declares both "checksum" and "signature". Pick one — a signature '
                . 'already covers the bytes a checksum would.',
                $sourceName
            ));
        }

        if ($signature !== null) {
            return self::signature($signature, $sourceName, $upstreamUrl);
        }

        if ($checksum !== null) {
            return self::checksum($checksum, $sourceName, $upstreamUrl);
        }

        return null;
    }

    /**
     * How long the digest is, in hex characters.
     *
     * @return int
     *   Twice the raw byte length.
     */
    public function digestLength(): int
    {
        return strlen(hash($this->algorithm, ''));
    }

    /**
     * Whether a sidecar has to be fetched before the body can be checked.
     *
     * @return bool
     *   TRUE when the assertion lives at a URL rather than in the config.
     */
    public function needsSidecar(): bool
    {
        return $this->url !== null;
    }

    /**
     * What this asserts, for a log line or a report.
     *
     * @return string
     *   A short human-readable description.
     */
    public function describe(): string
    {
        if ($this->mode === self::SIGNATURE) {
            return $this->algorithm . ' signature';
        }

        return $this->value !== null
            ? $this->algorithm . ' checksum pinned in config'
            : $this->algorithm . ' sidecar';
    }

    /**
     * Read a `checksum:` declaration in either form.
     *
     * @param mixed $declared
     *   An algorithm name, or a map.
     * @param string $sourceName
     *   Source name, for error messages.
     * @param string $upstreamUrl
     *   The list's URL, for the default sidecar location.
     *
     * @return self
     *   The verification.
     *
     * @throws SourceException
     *   When the declaration is malformed.
     */
    private static function checksum(mixed $declared, string $sourceName, string $upstreamUrl): self
    {
        if (is_string($declared)) {
            $declared = ['algorithm' => $declared];
        }

        if (!is_array($declared)) {
            throw new SourceException(sprintf(
                'Source "%s": "checksum" must be an algorithm name or a map, %s given.',
                $sourceName,
                gettype($declared)
            ));
        }

        $algorithm = self::algorithm($declared, self::CHECKSUM_ALGORITHMS, 'checksum', $sourceName);
        $value = $declared['value'] ?? null;

        if ($value !== null && !is_string($value)) {
            throw new SourceException(sprintf(
                'Source "%s": checksum.value must be a hex digest string, %s given.',
                $sourceName,
                gettype($value)
            ));
        }

        if (is_string($value)) {
            $value = strtolower(trim($value));
            $expected = strlen(hash($algorithm, ''));

            if (preg_match('/^[0-9a-f]{' . $expected . '}$/', $value) !== 1) {
                throw new SourceException(sprintf(
                    'Source "%s": checksum.value must be %d hex characters for %s, got %d.',
                    $sourceName,
                    $expected,
                    $algorithm,
                    strlen($value)
                ));
            }

            // Pinned in the config, so there is nothing to fetch and nothing an
            // upstream can restate. The strongest of the three, and the least
            // usable: every publish of the list is a commit here.
            return new self(self::CHECKSUM, $algorithm, null, $value);
        }

        return new self(
            self::CHECKSUM,
            $algorithm,
            self::sidecarUrl($declared, $upstreamUrl, '.' . $algorithm, $sourceName)
        );
    }

    /**
     * Read a `signature:` declaration.
     *
     * @param mixed $declared
     *   The map.
     * @param string $sourceName
     *   Source name, for error messages.
     * @param string $upstreamUrl
     *   The list's URL, for the default sidecar location.
     *
     * @return self
     *   The verification.
     *
     * @throws SourceException
     *   When the declaration is malformed or names no key.
     */
    private static function signature(mixed $declared, string $sourceName, string $upstreamUrl): self
    {
        if (!is_array($declared)) {
            throw new SourceException(sprintf(
                'Source "%s": "signature" must be a map with an algorithm and a public_key, %s given.',
                $sourceName,
                gettype($declared)
            ));
        }

        $algorithm = self::algorithm($declared, self::SIGNATURE_ALGORITHMS, 'signature', $sourceName);
        $publicKey = $declared['public_key'] ?? null;

        if (!is_string($publicKey) || trim($publicKey) === '') {
            throw new SourceException(sprintf(
                'Source "%s": signature.public_key is required — a signature with no pinned key '
                . 'verifies that the file was signed by whoever signed it.',
                $sourceName
            ));
        }

        return new self(
            self::SIGNATURE,
            $algorithm,
            self::sidecarUrl($declared, $upstreamUrl, '.sig', $sourceName),
            null,
            trim($publicKey)
        );
    }

    /**
     * Read the algorithm, defaulting to the first of the allowed set.
     *
     * @param array<array-key, mixed> $declared
     *   The declaration map.
     * @param array<int, string> $allowed
     *   Permitted algorithms.
     * @param string $key
     *   The declaring key, for the error message.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @return string
     *   One of $allowed.
     *
     * @throws SourceException
     *   When the named algorithm is not one of them.
     */
    private static function algorithm(array $declared, array $allowed, string $key, string $sourceName): string
    {
        $algorithm = $declared['algorithm'] ?? $allowed[0];

        if (!is_string($algorithm) || !in_array(strtolower($algorithm), $allowed, true)) {
            throw new SourceException(sprintf(
                'Source "%s": %s.algorithm must be one of %s, got %s.',
                $sourceName,
                $key,
                implode(', ', $allowed),
                is_string($algorithm) ? sprintf('"%s"', $algorithm) : gettype($algorithm)
            ));
        }

        return strtolower($algorithm);
    }

    /**
     * Where the sidecar lives.
     *
     * Defaults to the list's own URL with a suffix, which is what publishers
     * that ship one almost always do. A `url:` overrides it for the publishers
     * that keep digests in one file somewhere else.
     *
     * @param array<array-key, mixed> $declared
     *   The declaration map.
     * @param string $upstreamUrl
     *   The list's URL.
     * @param string $suffix
     *   Appended when no `url` is declared.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @return string
     *   The sidecar location.
     *
     * @throws SourceException
     *   When a declared `url` is not a non-empty string.
     */
    private static function sidecarUrl(array $declared, string $upstreamUrl, string $suffix, string $sourceName): string
    {
        $url = $declared['url'] ?? null;

        if ($url === null) {
            return $upstreamUrl . $suffix;
        }

        if (!is_string($url) || trim($url) === '') {
            throw new SourceException(sprintf(
                'Source "%s": the verification "url" must be a non-empty string.',
                $sourceName
            ));
        }

        return trim($url);
    }
}
