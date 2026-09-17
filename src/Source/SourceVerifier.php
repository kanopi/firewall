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
 * Checks fetched bytes against what the source said they would be (#365).
 *
 * Every failure here is a `SourceException`, which is what puts this on the
 * *existing* failure path rather than a new one: `SourceManager` already turns
 * that into `last_known_good`, `fail_open` or `abort` according to the source's
 * own policy. So a source that fails verification keeps serving its last known
 * good copy and never falls back to the unverified bytes — which is the
 * behaviour the feature needed and did not have to invent.
 *
 * Nothing in here is reached by a source that declares no verification.
 */
final class SourceVerifier
{
    /**
     * Raw byte length of an ed25519 public key.
     */
    private const ED25519_KEY_BYTES = 32;

    /**
     * Raw byte length of an ed25519 detached signature.
     */
    private const ED25519_SIGNATURE_BYTES = 64;

    /**
     * Assert that a body is what the source says it should be.
     *
     * @param SourceVerification $sourceVerification
     *   What the source asserts.
     * @param string $body
     *   The fetched bytes, before decompression — a digest is published over
     *   the artifact as distributed, so `ranges.json.gz` is hashed gzipped.
     * @param string|null $sidecar
     *   The fetched sidecar, or NULL when the digest is pinned in config.
     * @param string $sourceName
     *   Source name, for error messages.
     * @param string $fileName
     *   The list's file name, used to pick a line out of a multi-file sidecar.
     *
     * @throws SourceException
     *   When the body does not verify, or the sidecar cannot be read.
     */
    public function assert(
        SourceVerification $sourceVerification,
        string $body,
        ?string $sidecar,
        string $sourceName,
        string $fileName = ''
    ): void {
        if ($sourceVerification->mode === SourceVerification::SIGNATURE) {
            $this->assertSignature($sourceVerification, $body, (string) $sidecar, $sourceName);

            return;
        }

        $expected = $sourceVerification->value ?? $this->digestFrom(
            (string) $sidecar,
            $sourceVerification,
            $fileName,
            $sourceName
        );

        $actual = hash($sourceVerification->algorithm, $body);

        // Constant-time, even though neither side is secret here. It costs
        // nothing, and the alternative is a reviewer having to work out why
        // this one comparison is exempt from the rule the rest of the library
        // follows.
        if (!hash_equals($expected, $actual)) {
            throw new SourceException(sprintf(
                'Source "%s": %s checksum mismatch. Expected %s, got %s. The bytes are not the '
                . 'ones the publisher asserted — refusing them and keeping whatever was last '
                . 'verified.',
                $sourceName,
                $sourceVerification->algorithm,
                $this->abbreviate($expected),
                $this->abbreviate($actual)
            ));
        }
    }

    /**
     * Whether this host can verify ed25519 signatures.
     *
     * A seam, for the same reason `SourceLoader::gzipAvailable()` is one:
     * ext-sodium is either compiled in or it is not, and a test cannot take it
     * away.
     *
     * @return bool
     *   TRUE when libsodium's detached verify is available.
     */
    protected function sodiumAvailable(): bool
    {
        return function_exists('sodium_crypto_sign_verify_detached');
    }

    /**
     * The one call into ext-sodium.
     *
     * Also a seam, and for a second reason: the extension raises
     * `SodiumException` on a malformed argument. The lengths are checked before
     * anything reaches here, so on a correct build it cannot — but a source
     * failure that escapes as anything other than a `SourceException` bypasses
     * the `on_error` policy entirely, which is a worse outcome than the one it
     * would be reporting. Overriding this is how that path is exercised.
     *
     * @param string $signature
     *   The raw 64-byte signature.
     * @param string $body
     *   The bytes it covers.
     * @param string $publicKey
     *   The raw 32-byte public key.
     *
     * @return bool
     *   TRUE when the signature verifies.
     *
     * @throws \SodiumException
     *   When the extension rejects an argument.
     */
    protected function verifyDetached(string $signature, string $body, string $publicKey): bool
    {
        return sodium_crypto_sign_verify_detached($signature, $body, $publicKey);
    }

    /**
     * Verify a detached signature over the body.
     *
     * @param SourceVerification $sourceVerification
     *   What the source asserts.
     * @param string $body
     *   The fetched bytes.
     * @param string $signature
     *   The fetched signature, in any of the three encodings publishers use.
     * @param string $sourceName
     *   Source name, for error messages.
     *
     * @throws SourceException
     *   When the signature does not verify, or cannot be decoded.
     */
    private function assertSignature(
        SourceVerification $sourceVerification,
        string $body,
        string $signature,
        string $sourceName
    ): void {
        if (!$this->sodiumAvailable()) {
            // An error rather than a shrug. A source declaring a signature has
            // been told this list matters; running it unverified because the
            // host is missing an extension is the one outcome nobody asked for.
            throw new SourceException(sprintf(
                'Source "%s": declares an ed25519 signature but ext-sodium is not available, so '
                . 'nothing can verify it.',
                $sourceName
            ));
        }

        $key = $this->decodeBinary(
            (string) $sourceVerification->publicKey,
            self::ED25519_KEY_BYTES,
            'signature.public_key',
            $sourceName
        );

        $raw = $this->decodeBinary($signature, self::ED25519_SIGNATURE_BYTES, 'signature', $sourceName);

        try {
            $verified = $this->verifyDetached($raw, $body, $key);
        } catch (\SodiumException $sodiumException) {
            throw new SourceException(sprintf(
                'Source "%s": ed25519 verification failed: %s',
                $sourceName,
                $sodiumException->getMessage()
            ), 0, $sodiumException);
        }

        if (!$verified) {
            throw new SourceException(sprintf(
                'Source "%s": ed25519 signature does not verify against the pinned public key. '
                . 'Refusing the body and keeping whatever was last verified.',
                $sourceName
            ));
        }
    }

    /**
     * Pull the digest for this file out of a sidecar.
     *
     * Handles the three shapes a `.sha256` file is published in:
     *
     * ```
     * d41d8cd9…                       bare digest
     * d41d8cd9…  blocklist.txt        coreutils, one file
     * d41d8cd9… *blocklist.txt        coreutils, binary mode
     * d41d8cd9…  a.txt                a checksums file covering several
     * 2f3a91bb…  b.txt
     * ```
     *
     * @param string $sidecar
     *   The fetched sidecar body.
     * @param SourceVerification $sourceVerification
     *   What the source asserts, for the expected digest length.
     * @param string $fileName
     *   The list's file name, matched against a multi-line sidecar.
     * @param string $sourceName
     *   Source name, for error messages.
     *
     * @return string
     *   The lowercase hex digest.
     *
     * @throws SourceException
     *   When no digest for this file can be found.
     */
    private function digestFrom(
        string $sidecar,
        SourceVerification $sourceVerification,
        string $fileName,
        string $sourceName
    ): string {
        $length = $sourceVerification->digestLength();
        $bare = strtolower(trim($sidecar));

        if (preg_match('/^[0-9a-f]{' . $length . '}$/', $bare) === 1) {
            return $bare;
        }

        $digests = [];

        foreach (preg_split('/\R/', $sidecar) ?: [] as $line) {
            if (preg_match('/^([0-9a-fA-F]{' . $length . '})[ \t]+\*?(\S.*)$/', trim($line), $match) === 1) {
                $digests[trim($match[2])] = strtolower($match[1]);
            }
        }

        if ($digests === []) {
            throw new SourceException(sprintf(
                'Source "%s": the %s sidecar contains no %d-character digest. Fetched %s.',
                $sourceName,
                $sourceVerification->algorithm,
                $length,
                $sidecar === '' ? 'an empty body' : sprintf('"%s"', $this->abbreviate(trim($sidecar), 40))
            ));
        }

        if (isset($digests[$fileName])) {
            return $digests[$fileName];
        }

        if (count($digests) === 1) {
            // One line and a name that does not match. A publisher renaming
            // their own file, or a URL fetched through a rewriting proxy — and
            // refusing over the label while the digest is right there would be
            // pedantry with an outage attached.
            return (string) array_values($digests)[0];
        }

        throw new SourceException(sprintf(
            'Source "%s": the %s sidecar lists %d files and none of them is "%s". Point '
            . 'checksum.url at a sidecar for this file, or pin checksum.value.',
            $sourceName,
            $sourceVerification->algorithm,
            count($digests),
            $fileName
        ));
    }

    /**
     * Decode a key or signature from whichever encoding it arrived in.
     *
     * Raw bytes, hex, or base64 — publishers use all three, and a `.sig` file
     * is usually raw while a key pasted into YAML never is.
     *
     * @param string $raw
     *   The value as fetched or configured.
     * @param int $bytes
     *   How many raw bytes it must decode to.
     * @param string $what
     *   What is being decoded, for the error message.
     * @param string $sourceName
     *   Source name, for the error message.
     *
     * @return string
     *   The raw bytes.
     *
     * @throws SourceException
     *   When it decodes to the wrong length in every encoding.
     */
    private function decodeBinary(string $raw, int $bytes, string $what, string $sourceName): string
    {
        // Length first, before any trimming: a raw signature can legitimately
        // begin or end with a byte that trim() would eat.
        if (strlen($raw) === $bytes) {
            return $raw;
        }

        $trimmed = trim($raw);

        if (strlen($trimmed) === $bytes * 2 && preg_match('/^[0-9a-fA-F]+$/', $trimmed) === 1) {
            return (string) hex2bin($trimmed);
        }

        $decoded = base64_decode(strtr($trimmed, '-_', '+/'), true);

        if (is_string($decoded) && strlen($decoded) === $bytes) {
            return $decoded;
        }

        throw new SourceException(sprintf(
            'Source "%s": %s is not %d bytes of raw, hex or base64 data.',
            $sourceName,
            $what,
            $bytes
        ));
    }

    /**
     * Shorten a digest for a message.
     *
     * The whole thing is 64 characters of noise that nobody compares by eye;
     * enough of it to tell two apart is the useful amount.
     *
     * @param string $value
     *   The value to shorten.
     * @param int $keep
     *   How many characters to keep.
     *
     * @return string
     *   The abbreviated value.
     */
    private function abbreviate(string $value, int $keep = 16): string
    {
        return strlen($value) <= $keep ? $value : substr($value, 0, $keep) . '…';
    }
}
