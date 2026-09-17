<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceVerification;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Reading `checksum:` and `signature:` off a source declaration (#365).
 */
class SourceVerificationTest extends AbstractTestCase
{
    private const UPSTREAM = 'https://example.org/v1/blocklist.txt';

    public function testASourceDeclaringNeitherIsUnverified(): void
    {
        $this->assertNull($this->read([]));
    }

    /**
     * The shorthand most configs will use: an algorithm name, and the sidecar
     * location derived from the list's own URL.
     */
    public function testTheStringShorthandDerivesTheSidecarLocation(): void
    {
        $verification = $this->read(['checksum' => 'sha256']);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame(SourceVerification::CHECKSUM, $verification->mode);
        $this->assertSame('sha256', $verification->algorithm);
        $this->assertSame(self::UPSTREAM . '.sha256', $verification->url);
        $this->assertTrue($verification->needsSidecar());
        $this->assertSame('sha256 sidecar', $verification->describe());
    }

    /**
     * The suffix follows the algorithm, so `sha512` looks for `.sha512`.
     */
    public function testTheSidecarSuffixFollowsTheAlgorithm(): void
    {
        $verification = $this->read(['checksum' => ['algorithm' => 'sha512']]);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame(self::UPSTREAM . '.sha512', $verification->url);
        $this->assertSame(128, $verification->digestLength());
    }

    /**
     * Publishers who keep every digest in one file need to say where it is.
     */
    public function testAnExplicitSidecarUrlWins(): void
    {
        $verification = $this->read([
            'checksum' => ['algorithm' => 'sha256', 'url' => ' https://example.org/SHA256SUMS '],
        ]);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame('https://example.org/SHA256SUMS', $verification->url);
    }

    /**
     * A digest pinned in configuration fetches nothing.
     */
    public function testAPinnedDigestNeedsNoSidecar(): void
    {
        $digest = hash('sha256', 'whatever');
        $verification = $this->read(['checksum' => ['value' => strtoupper($digest)]]);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame($digest, $verification->value, 'The pinned digest should be normalised to lowercase');
        $this->assertNull($verification->url);
        $this->assertFalse($verification->needsSidecar());
        $this->assertSame('sha256 checksum pinned in config', $verification->describe());
    }

    public function testASignatureDerivesItsOwnSidecarAndKeepsTheKey(): void
    {
        $verification = $this->read([
            'signature' => ['algorithm' => 'ed25519', 'public_key' => ' abc123 '],
        ]);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame(SourceVerification::SIGNATURE, $verification->mode);
        $this->assertSame(self::UPSTREAM . '.sig', $verification->url);
        $this->assertSame('abc123', $verification->publicKey);
        $this->assertSame('ed25519 signature', $verification->describe());
    }

    /**
     * `algorithm` is optional on a signature — there is one.
     */
    public function testTheSignatureAlgorithmDefaults(): void
    {
        $verification = $this->read(['signature' => ['public_key' => 'abc123']]);

        $this->assertInstanceOf(SourceVerification::class, $verification);
        $this->assertSame('ed25519', $verification->algorithm);
    }

    /**
     * Two assertions about the same bytes is a config somebody is midway
     * through changing. Guessing which half they meant is how the weaker one
     * ends up being the one that runs.
     */
    public function testDeclaringBothIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('declares both "checksum" and "signature"');

        $this->read(['checksum' => 'sha256', 'signature' => ['public_key' => 'k']]);
    }

    /**
     * A signature with no pinned key verifies that the file was signed by
     * whoever signed it, which is not a fact about anything.
     */
    public function testASignatureWithoutAKeyIsRefused(): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('signature.public_key is required');

        $this->read(['signature' => ['algorithm' => 'ed25519']]);
    }

    #[DataProvider('malformedProvider')]
    public function testMalformedDeclarationsAreRefused(array $declaration, string $expected): void
    {
        $this->expectException(SourceException::class);
        $this->expectExceptionMessage($expected);

        $this->read($declaration);
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function malformedProvider(): array
    {
        return [
            'checksum is a boolean' => [
                ['checksum' => true],
                '"checksum" must be an algorithm name or a map, boolean given',
            ],
            'checksum is a number' => [
                ['checksum' => 256],
                '"checksum" must be an algorithm name or a map, integer given',
            ],
            'md5 is not offered' => [
                ['checksum' => 'md5'],
                'checksum.algorithm must be one of sha256, sha384, sha512, got "md5"',
            ],
            'algorithm is not a string' => [
                ['checksum' => ['algorithm' => true]],
                'checksum.algorithm must be one of sha256, sha384, sha512, got boolean',
            ],
            'pinned value is not a string' => [
                ['checksum' => ['value' => 12345]],
                'checksum.value must be a hex digest string, integer given',
            ],
            'pinned value is the wrong length' => [
                ['checksum' => ['value' => 'deadbeef']],
                'checksum.value must be 64 hex characters for sha256, got 8',
            ],
            'pinned value is not hex' => [
                ['checksum' => ['value' => str_repeat('z', 64)]],
                'checksum.value must be 64 hex characters for sha256',
            ],
            'sidecar url is empty' => [
                ['checksum' => ['algorithm' => 'sha256', 'url' => '   ']],
                'the verification "url" must be a non-empty string',
            ],
            'sidecar url is not a string' => [
                ['checksum' => ['algorithm' => 'sha256', 'url' => 42]],
                'the verification "url" must be a non-empty string',
            ],
            'signature is a string' => [
                ['signature' => 'ed25519'],
                '"signature" must be a map with an algorithm and a public_key, string given',
            ],
            'unknown signature algorithm' => [
                ['signature' => ['algorithm' => 'rsa', 'public_key' => 'k']],
                'signature.algorithm must be one of ed25519, got "rsa"',
            ],
            'signature key is blank' => [
                ['signature' => ['public_key' => '   ']],
                'signature.public_key is required',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $declaration
     */
    private function read(array $declaration): ?SourceVerification
    {
        return SourceVerification::fromDeclaration($declaration, 'a-feed', self::UPSTREAM);
    }
}
