<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Source;

use Kanopi\Firewall\Exception\SourceException;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;
use Kanopi\Firewall\Source\SourceLoader;
use Kanopi\Firewall\Source\SourceManager;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;

/**
 * Verification as the loader and the manager actually run it (#365).
 *
 * The unit tests above check the digest arithmetic. These check the thing that
 * matters operationally: that a source failing verification takes the existing
 * `on_error` path — keeping its last known good copy, never the bytes it just
 * refused.
 */
class SourceVerificationFlowTest extends AbstractTestCase
{
    private const BODY = "3.5.140.0/22\n18.34.32.0/20\n";

    private string $workspace;

    protected function setUp(): void
    {
        parent::setUp();
        $this->workspace = sys_get_temp_dir() . '/firewall-verify-' . bin2hex(random_bytes(6));
        mkdir($this->workspace . '/cache', 0775, true);
    }

    protected function tearDown(): void
    {
        foreach ((array) glob($this->workspace . '/{,cache/}*', GLOB_BRACE) as $path) {
            if (is_string($path) && is_file($path)) {
                @unlink($path);
            }
        }

        @rmdir($this->workspace . '/cache');
        @rmdir($this->workspace);
        parent::tearDown();
    }

    /**
     * A sidecar beside the list, fetched by the same fetcher that read the
     * list — which for a local file means read off the same disk.
     */
    public function testASidecarBesideTheListIsFoundAndChecked(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write('blocklist.txt.sha256', hash('sha256', self::BODY) . '  blocklist.txt' . "\n");

        $entries = $this->loader()->load($this->definition($path, ['checksum' => 'sha256']));

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $entries);
    }

    public function testATamperedBodyIsRefused(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write('blocklist.txt.sha256', hash('sha256', 'what the publisher meant'));

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('sha256 checksum mismatch');

        $this->loader()->load($this->definition($path, ['checksum' => 'sha256']));
    }

    /**
     * The behaviour the feature is for: a body that does not verify never
     * becomes the active list, and the last verified copy keeps serving.
     */
    public function testAFailedVerificationKeepsTheLastKnownGoodCopy(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write('blocklist.txt.sha256', hash('sha256', self::BODY));

        $declaration = ['upstream' => $path, 'checksum' => 'sha256', 'name' => 'a-feed'];
        $sourceManager = new SourceManager($this->loader(), $this->cache());

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $sourceManager->load([$declaration], true));

        // The list is replaced and the sidecar is not — a CDN object swapped, a
        // repository pushed to, a mirror serving somebody else's file.
        $this->write('blocklist.txt', "0.0.0.0/0\n");

        $this->assertSame(
            ['3.5.140.0/22', '18.34.32.0/20'],
            $sourceManager->load([$declaration], true),
            'The refused body was used instead of the last verified one'
        );

        $this->assertStringContainsString('checksum mismatch', $sourceManager->errors()[0]['message']);
    }

    /**
     * `required: true` turns the same refusal into a bootstrap failure, for an
     * allow list where quietly serving a stale copy is the wrong direction.
     */
    public function testARequiredSourceThatFailsVerificationAborts(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write('blocklist.txt.sha256', hash('sha256', 'something else'));

        $sourceManager = new SourceManager($this->loader(), $this->cache());

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('checksum mismatch');

        $sourceManager->load([['upstream' => $path, 'checksum' => 'sha256', 'required' => true]], true);
    }

    public function testAMissingSidecarIsAFailureRatherThanASkip(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('cannot read');

        $this->loader()->load($this->definition($path, ['checksum' => 'sha256']));
    }

    public function testAnEmptySidecarIsAFailure(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write('blocklist.txt.sha256', '');

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('came back empty');

        $this->loader()->load($this->definition($path, ['checksum' => 'sha256']));
    }

    /**
     * A digest pinned in config touches nothing on the wire — which is also
     * what makes it the strongest of the three and the least usable.
     */
    public function testAPinnedDigestFetchesNoSidecar(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);

        $entries = $this->loader()->load($this->definition($path, [
            'checksum' => ['value' => hash('sha256', self::BODY)],
        ]));

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $entries);
    }

    /**
     * The digest covers the artifact as distributed, so a gzipped list is
     * hashed gzipped — before the loader decompresses it.
     */
    public function testACompressedListIsCheckedBeforeItIsDecompressed(): void
    {
        $compressed = (string) gzencode(self::BODY);
        $path = $this->write('blocklist.txt.gz', $compressed);
        $this->write('blocklist.txt.gz.sha256', hash('sha256', $compressed));

        $entries = $this->loader()->load($this->definition($path, ['checksum' => 'sha256', 'format' => 'txt']));

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $entries);
    }

    public function testAnEd25519SignatureIsVerifiedEndToEnd(): void
    {
        $pair = sodium_crypto_sign_keypair();
        $path = $this->write('blocklist.txt', self::BODY);
        $this->write(
            'blocklist.txt.sig',
            sodium_crypto_sign_detached(self::BODY, sodium_crypto_sign_secretkey($pair))
        );

        $entries = $this->loader()->load($this->definition($path, [
            'signature' => [
                'algorithm' => 'ed25519',
                'public_key' => base64_encode(sodium_crypto_sign_publickey($pair)),
            ],
        ]));

        $this->assertSame(['3.5.140.0/22', '18.34.32.0/20'], $entries);
    }

    /**
     * Cached entries came from bytes that nothing checked. Adding a `checksum:`
     * has to invalidate them, or the first thing the new setting does is serve
     * the unverified copy it was added to stop trusting.
     */
    public function testAddingVerificationChangesTheFingerprint(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);

        $unverified = $this->definition($path, [])->fingerprint();
        $checksummed = $this->definition($path, ['checksum' => 'sha256'])->fingerprint();
        $signed = $this->definition($path, [
            'signature' => ['public_key' => 'a-key'],
        ])->fingerprint();

        $this->assertNotSame($unverified, $checksummed);
        $this->assertNotSame($checksummed, $signed);
    }

    /**
     * Verification runs before the body-hash shortcut, not after. That hash
     * compares this fetch against the previous one; it has never said anything
     * about authenticity, and a source given a `checksum:` after its cache was
     * warmed has to be checked on the next refresh rather than the next change.
     */
    public function testAWarmCacheDoesNotSkipTheCheck(): void
    {
        $path = $this->write('blocklist.txt', self::BODY);
        $unverified = ['upstream' => $path, 'name' => 'a-feed'];

        $this->assertNotSame([], $this->loader()->load(SourceDefinition::fromArray($unverified), true));

        // Same bytes, same upstream, cache warm — and now a sidecar that does
        // not describe them.
        $this->write('blocklist.txt.sha256', hash('sha256', 'a different file'));

        $this->expectException(SourceException::class);
        $this->expectExceptionMessage('checksum mismatch');

        $this->loader()->load(SourceDefinition::fromArray($unverified + ['checksum' => 'sha256']), true);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function definition(string $path, array $options): SourceDefinition
    {
        return SourceDefinition::fromArray(['upstream' => $path, 'name' => 'a-feed'] + $options);
    }

    private function loader(): SourceLoader
    {
        return new SourceLoader(sourceCache: $this->cache());
    }

    private function cache(): SourceCache
    {
        return new SourceCache($this->workspace . '/cache');
    }

    private function write(string $name, string $contents): string
    {
        $path = $this->workspace . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }
}
