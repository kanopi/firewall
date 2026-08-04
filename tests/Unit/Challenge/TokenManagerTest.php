<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Request;

final class TokenManagerTest extends AbstractTestCase
{
    private const SECRET = 'test-secret-value-do-not-reuse-in-prod';

    public function testEmptySecretThrows(): void
    {
        $this->expectException(ConfigurationException::class);
        new TokenManager('');
    }

    public function testMintAndVerifyRoundTrip(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        $token = $manager->mint($request, 3600);

        $this->assertNotEmpty($token);
        $this->assertStringContainsString('.', $token);
        $this->assertTrue($manager->verify($token, $request));
    }

    public function testVerifyFailsForDifferentIp(): void
    {
        $manager = new TokenManager(self::SECRET);
        $original = $this->getRequest('10.0.0.5');
        $other = $this->getRequest('10.0.0.6');

        $token = $manager->mint($original, 3600);

        $this->assertFalse($manager->verify($token, $other));
    }

    public function testVerifyFailsForTamperedPayload(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        $token = $manager->mint($request, 3600);
        [$payload, $signature] = explode('.', $token, 2);
        $tampered = self::flipFirstChar($payload) . '.' . $signature;

        $this->assertFalse($manager->verify($tampered, $request));
    }

    public function testVerifyFailsForTamperedSignature(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        $token = $manager->mint($request, 3600);
        [$payload, $signature] = explode('.', $token, 2);
        $tamperedSig = $payload . '.' . self::flipFirstChar($signature);

        $this->assertFalse($manager->verify($tamperedSig, $request));
    }

    /**
     * Replace the first character of $s with a different one, so the
     * resulting string is always distinct from the input — even when the
     * input is random base64url and may not contain any chosen target
     * character.
     */
    private static function flipFirstChar(string $s): string
    {
        if ($s === '') {
            return 'A';
        }
        $replacement = $s[0] === 'A' ? 'B' : 'A';
        return $replacement . substr($s, 1);
    }

    public function testVerifyFailsForExpiredToken(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        // Mint a token with negative TTL — TokenManager floors that to 3600,
        // so instead we construct an expired payload directly by signing
        // hand-rolled JSON with `sign()`.
        $expiredPayload = json_encode(['ip' => '10.0.0.5', 'exp' => time() - 60, 'nonce' => 'abc']);
        $encoded = rtrim(strtr(base64_encode((string) $expiredPayload), '+/', '-_'), '=');
        $expiredToken = $encoded . '.' . $manager->sign($encoded);

        $this->assertFalse($manager->verify($expiredToken, $request));
    }

    public function testVerifyFailsForGarbageInput(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        $this->assertFalse($manager->verify('', $request));
        $this->assertFalse($manager->verify('no-dot', $request));
        $this->assertFalse($manager->verify('.', $request));
        $this->assertFalse($manager->verify('a.', $request));
        $this->assertFalse($manager->verify('.b', $request));
        $this->assertFalse($manager->verify('a.b.c', $request));
        $this->assertFalse($manager->verify('!!.!!', $request));
    }

    public function testSignAndVerifySignature(): void
    {
        $manager = new TokenManager(self::SECRET);

        $data = '8|' . (time() + 300);
        $sig = $manager->sign($data);

        $this->assertNotEmpty($sig);
        $this->assertTrue($manager->verifySignature($data, $sig));
        $this->assertFalse($manager->verifySignature($data . 'x', $sig));
        $this->assertFalse($manager->verifySignature($data, $sig . 'x'));
    }

    public function testTtlFallsBackTo3600WhenNonPositive(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        // Negative TTL should still mint a verifiable token (TokenManager
        // floors to 3600), and that token should verify cleanly.
        $token = $manager->mint($request, -1);
        $this->assertTrue($manager->verify($token, $request));
    }

    public function testTokenIsNotAcceptedByADifferentAudience(): void
    {
        // The exact deployment the demo now ships: two instances, one
        // secret, different challenge providers. A token earned on the
        // trivial math challenge must not open an ALTCHA-protected route.
        $math = new TokenManager(self::SECRET, 'math');
        $altcha = new TokenManager(self::SECRET, 'altcha');
        $request = $this->getRequest('10.1.2.3');

        $token = $math->mint($request, 3600);

        $this->assertTrue($math->verify($token, $request));
        $this->assertFalse($altcha->verify($token, $request));
    }

    public function testSameAudienceStillInteroperates(): void
    {
        // Two processes of the same deployment must still share tokens.
        $minter = new TokenManager(self::SECRET, 'altcha');
        $verifier = new TokenManager(self::SECRET, 'altcha');
        $request = $this->getRequest('10.1.2.3');

        $this->assertTrue($verifier->verify($minter->mint($request, 3600), $request));
    }

    public function testCustomAudienceSeparatesSameProviderInstances(): void
    {
        $public = new TokenManager(self::SECRET, 'public-site');
        $admin = new TokenManager(self::SECRET, 'admin-portal');
        $request = $this->getRequest('10.1.2.3');

        $this->assertFalse($admin->verify($public->mint($request, 3600), $request));
    }

    public function testTokenWithoutAudienceClaimIsRejected(): void
    {
        // Forge a pre-upgrade token: correctly signed, but no `aud`.
        // Verification must fail closed rather than accept it.
        $manager = new TokenManager(self::SECRET, 'math');
        $request = $this->getRequest('10.1.2.3');

        $payload = ['ip' => '10.1.2.3', 'exp' => time() + 3600, 'nonce' => str_repeat('a', 32)];
        $encoded = rtrim(strtr(base64_encode((string) json_encode($payload)), '+/', '-_'), '=');
        $signature = rtrim(
            strtr(base64_encode(hash_hmac('sha256', $encoded, self::SECRET, true)), '+/', '-_'),
            '='
        );

        $this->assertFalse($manager->verify($encoded . '.' . $signature, $request));
    }

    public function testAudienceIsCoveredByTheSignature(): void
    {
        // Swapping `aud` in the payload must invalidate the HMAC, so an
        // attacker cannot re-scope a token they already hold.
        $manager = new TokenManager(self::SECRET, 'math');
        $request = $this->getRequest('10.1.2.3');

        [$payloadPart, $signature] = explode('.', $manager->mint($request, 3600), 2);
        $padded = $payloadPart . str_repeat('=', (4 - strlen($payloadPart) % 4) % 4);
        $json = base64_decode(strtr($padded, '-_', '+/'), true);
        $payload = json_decode((string) $json, true);
        $this->assertIsArray($payload);

        $payload['aud'] = 'altcha';
        $tampered = rtrim(strtr(base64_encode((string) json_encode($payload)), '+/', '-_'), '=');

        $altcha = new TokenManager(self::SECRET, 'altcha');
        $this->assertFalse($altcha->verify($tampered . '.' . $signature, $request));
    }

    /**
     * Payloads that survive the signature check but are still not tokens.
     *
     * Signature verification happens before the payload is parsed, so a
     * caller who holds the secret can present correctly-signed rubbish. The
     * decode and shape checks after `hash_equals()` are the last line of
     * defence, and each needs its own exercise. Every case here is signed
     * with the real secret precisely so the test reaches past the HMAC.
     *
     * @return array<string, array{0: string}>
     *   Keyed by what is wrong with the payload.
     */
    public static function correctlySignedRubbishProvider(): array
    {
        return [
            // Outside the base64url alphabet, so strict decoding refuses it.
            'not base64url' => ['@@@@'],
            'valid base64, not json' => [self::encode('definitely not json')],
            'json scalar rather than object' => [self::encode('"a string"')],
            'json null' => [self::encode('null')],
            'object missing ip' => [self::encode('{"exp":9999999999,"aud":""}')],
            'object missing exp' => [self::encode('{"ip":"10.1.2.3","aud":""}')],
            // `exp` has to be an integer: a numeric string would otherwise
            // reach the comparison against time() and behave unpredictably.
            'exp as a numeric string' => [self::encode('{"ip":"10.1.2.3","exp":"9999999999","aud":""}')],
            'exp as a float' => [self::encode('{"ip":"10.1.2.3","exp":9999999999.5,"aud":""}')],
        ];
    }

    #[DataProvider('correctlySignedRubbishProvider')]
    public function testCorrectlySignedRubbishIsStillRejected(string $payloadEncoded): void
    {
        $manager = new TokenManager(self::SECRET);

        // sign() covers exactly the string verify() signs, so this token has
        // a genuinely valid signature over an invalid payload.
        $token = $payloadEncoded . '.' . $manager->sign($payloadEncoded);

        $this->assertFalse($manager->verify($token, $this->getRequest('10.1.2.3')));
    }

    /**
     * base64url-encode without padding, matching TokenManager's wire format.
     */
    private static function encode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
