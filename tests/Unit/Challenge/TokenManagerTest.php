<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Unit\Challenge;

use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Tests\Unit\AbstractTestCase;
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
        $tampered = strtr($payload, ['A' => 'B', 'a' => 'b']) . '.' . $signature;

        $this->assertFalse($manager->verify($tampered, $request));
    }

    public function testVerifyFailsForTamperedSignature(): void
    {
        $manager = new TokenManager(self::SECRET);
        $request = $this->getRequest('10.0.0.5');

        $token = $manager->mint($request, 3600);
        [$payload, $signature] = explode('.', $token, 2);
        $tamperedSig = $payload . '.' . strtr($signature, ['A' => 'B', 'a' => 'b']);

        $this->assertFalse($manager->verify($tamperedSig, $request));
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
}
