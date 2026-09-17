<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceVerification;
use Kanopi\Firewall\Source\SourceVerifier;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Checking fetched bytes against what a source asserts about them (#365).
 */
class SourceVerifierTest extends AbstractTestCase
{
    private const BODY = "3.5.140.0/22\n18.34.32.0/20\n";

    private const UPSTREAM = 'https://example.org/v1/blocklist.txt';

    /**
     * Every shape a published `.sha256` comes in.
     */
    #[DataProvider('sidecarProvider')]
    public function testASidecarIsReadInEveryPublishedShape(string $sidecar): void
    {
        $this->verifier()->assert($this->checksum(), self::BODY, $sidecar, 'a-feed', 'blocklist.txt');

        $this->assertTrue(true, 'A body matching the sidecar verifies');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function sidecarProvider(): array
    {
        $digest = hash('sha256', self::BODY);

        return [
            'bare digest' => [$digest],
            'bare digest with trailing newline' => [$digest . "\n"],
            'uppercase' => [strtoupper($digest)],
            'coreutils text mode' => [$digest . '  blocklist.txt' . "\n"],
            'coreutils binary mode' => [$digest . ' *blocklist.txt' . "\n"],
            'tab separated' => [$digest . "\tblocklist.txt\n"],
            'one file, a different name' => [$digest . "  renamed-by-the-publisher.txt\n"],
            'several files, ours among them' => [
                hash('sha256', 'other') . "  other.txt\n" . $digest . "  blocklist.txt\n",
            ],
            'several files, CRLF' => [
                hash('sha256', 'other') . "  other.txt\r\n" . $digest . "  blocklist.txt\r\n",
            ],
        ];
    }

    /**
     * The failure this exists for.
     */
    public function testABodyThatIsNotWhatWasPublishedIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('sha256 checksum mismatch');

        $this->verifier()->assert($this->checksum(), 'tampered', hash('sha256', self::BODY), 'a-feed');
    }

    public function testAPinnedDigestIsCheckedWithoutASidecar(): void
    {
        $verification = $this->read(['checksum' => ['value' => hash('sha256', self::BODY)]]);

        $this->verifier()->assert($verification, self::BODY, null, 'a-feed');

        $this->assertTrue(true, 'A body matching the pinned digest verifies');
    }

    public function testAPinnedDigestStillRefusesTheWrongBody(): void
    {
        $verification = $this->read(['checksum' => ['value' => hash('sha256', self::BODY)]]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('checksum mismatch');

        $this->verifier()->assert($verification, 'tampered', null, 'a-feed');
    }

    #[DataProvider('unreadableSidecarProvider')]
    public function testASidecarThatCarriesNoUsableDigestIsRefused(string $sidecar, string $expected): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        $this->verifier()->assert($this->checksum(), self::BODY, $sidecar, 'a-feed', 'blocklist.txt');
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function unreadableSidecarProvider(): array
    {
        return [
            'empty' => ['', 'contains no 64-character digest. Fetched an empty body'],
            'an HTML error page' => [
                '<html><body>404 Not Found</body></html>',
                'contains no 64-character digest',
            ],
            'a digest of the wrong length' => [hash('sha1', self::BODY), 'contains no 64-character digest'],
            'several files, none of them ours' => [
                hash('sha256', 'a') . "  a.txt\n" . hash('sha256', 'b') . "  b.txt\n",
                'lists 2 files and none of them is "blocklist.txt"',
            ],
        ];
    }

    /**
     * A digest is published over the artifact as distributed, so the caller
     * hands over the bytes before decompression. Stated as a test because the
     * opposite is the natural thing to write.
     */
    public function testTheDigestCoversTheBytesAsFetched(): void
    {
        $compressed = (string) gzencode(self::BODY);

        $this->verifier()->assert($this->checksum(), $compressed, hash('sha256', $compressed), 'a-feed');

        $this->assertTrue(true, 'The compressed bytes are what the digest covers');
    }

    #[DataProvider('signatureEncodingProvider')]
    public function testASignatureVerifiesInEveryEncodingPublishersUse(string $encode): void
    {
        [$verification, $signature] = $this->signed($encode);

        $this->verifier()->assert($verification, self::BODY, $signature, 'a-feed');

        $this->assertTrue(true, 'A genuine signature verifies however it is encoded');
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function signatureEncodingProvider(): array
    {
        return [
            'raw bytes, as a .sig file holds them' => ['raw'],
            'hex' => ['hex'],
            'base64' => ['base64'],
            'base64url' => ['base64url'],
            'base64 with a trailing newline' => ['base64-newline'],
        ];
    }

    public function testASignatureOverDifferentBytesDoesNotVerify(): void
    {
        [$verification, $signature] = $this->signed('base64');

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('does not verify against the pinned public key');

        $this->verifier()->assert($verification, 'tampered', $signature, 'a-feed');
    }

    /**
     * The point of pinning the key: a valid signature by somebody else is not
     * a valid signature.
     */
    public function testASignatureByAnotherKeyDoesNotVerify(): void
    {
        [$verification] = $this->signed('base64');
        $otherPair = sodium_crypto_sign_keypair();
        $forged = base64_encode(sodium_crypto_sign_detached(self::BODY, sodium_crypto_sign_secretkey($otherPair)));

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('does not verify against the pinned public key');

        $this->verifier()->assert($verification, self::BODY, $forged, 'a-feed');
    }

    #[DataProvider('undecodableProvider')]
    public function testAKeyOrSignatureOfTheWrongLengthIsRefused(string $key, string $signature, string $expected): void
    {
        $verification = $this->read(['signature' => ['public_key' => $key]]);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        $this->verifier()->assert($verification, self::BODY, $signature, 'a-feed');
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function undecodableProvider(): array
    {
        $pair = sodium_crypto_sign_keypair();
        $key = base64_encode(sodium_crypto_sign_publickey($pair));
        $signature = base64_encode(sodium_crypto_sign_detached(self::BODY, sodium_crypto_sign_secretkey($pair)));

        return [
            'key is not 32 bytes' => [
                base64_encode('too short'),
                $signature,
                'signature.public_key is not 32 bytes of raw, hex or base64 data',
            ],
            'key is prose' => [
                'paste your key here',
                $signature,
                'signature.public_key is not 32 bytes',
            ],
            'signature is not 64 bytes' => [
                $key,
                base64_encode('too short'),
                'signature is not 64 bytes of raw, hex or base64 data',
            ],
            'signature is an HTML error page' => [
                $key,
                '<html><body>404 Not Found</body></html>',
                'signature is not 64 bytes',
            ],
        ];
    }

    /**
     * A source declaring a signature has been told this list matters. Running
     * it unverified because the host is missing an extension is the one
     * outcome nobody asked for.
     */
    public function testAHostWithoutSodiumRefusesRatherThanSkips(): void
    {
        [$verification, $signature] = $this->signed('base64');

        $verifier = new class extends SourceVerifier {
            protected function sodiumAvailable(): bool
            {
                return false;
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('ext-sodium is not available, so nothing can verify it');

        $verifier->assert($verification, self::BODY, $signature, 'a-feed');
    }

    /**
     * The lengths are checked before anything reaches the extension, so on a
     * correct build this cannot happen. It is caught anyway because a failure
     * escaping as something other than a SourceException would bypass the
     * source's `on_error` policy — a worse outcome than the one it reports.
     */
    public function testAThrowFromTheExtensionArrivesAsASourceFailure(): void
    {
        [$verification, $signature] = $this->signed('base64');

        $verifier = new class extends SourceVerifier {
            protected function verifyDetached(string $signature, string $body, string $publicKey): bool
            {
                throw new \SodiumException('public key size should be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes');
            }
        };

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('ed25519 verification failed: public key size should be');

        $verifier->assert($verification, self::BODY, $signature, 'a-feed');
    }

    /**
     * Build a signed body and the verification that checks it.
     *
     * @return array{0: SourceVerification, 1: string}
     */
    private function signed(string $encode): array
    {
        $pair = sodium_crypto_sign_keypair();
        $raw = sodium_crypto_sign_detached(self::BODY, sodium_crypto_sign_secretkey($pair));
        $key = sodium_crypto_sign_publickey($pair);

        $signature = match ($encode) {
            'raw' => $raw,
            'hex' => bin2hex($raw),
            'base64url' => strtr(base64_encode($raw), '+/', '-_'),
            'base64-newline' => base64_encode($raw) . "\n",
            default => base64_encode($raw),
        };

        return [$this->read(['signature' => ['public_key' => base64_encode($key)]]), $signature];
    }

    private function checksum(): SourceVerification
    {
        return $this->read(['checksum' => 'sha256']);
    }

    /**
     * @param array<string, mixed> $declaration
     */
    private function read(array $declaration): SourceVerification
    {
        $verification = SourceVerification::fromDeclaration($declaration, 'a-feed', self::UPSTREAM);
        $this->assertInstanceOf(SourceVerification::class, $verification);

        return $verification;
    }

    private function verifier(): SourceVerifier
    {
        return new SourceVerifier();
    }
}
