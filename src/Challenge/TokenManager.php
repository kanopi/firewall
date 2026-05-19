<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Kanopi\Firewall\Exception\ConfigurationException;
use Symfony\Component\HttpFoundation\Request;

/**
 * Mints and verifies HMAC-signed challenge pass tokens.
 *
 * Tokens are stateless: the server holds no per-token record. Verification
 * relies purely on the embedded payload (IP, expiry, nonce) and HMAC
 * signature. This keeps the firewall horizontally scalable without a shared
 * session store, at the cost of being unable to revoke a single token before
 * it expires (rotating the secret invalidates everything).
 *
 * Wire format: `base64url(payload).base64url(hmac)`
 *   payload = JSON{ip, exp, nonce}
 *   hmac    = HMAC-SHA256(payload, secret)
 *
 * Token binding (verified on every request):
 *   - `ip`    must equal `$request->getClientIp()` at verify time.
 *   - `exp`   is a unix timestamp; tokens past it are rejected.
 *   - `nonce` is 128 random bits to keep two same-second mints distinct in
 *             downstream logs and to prevent precomputed-token attacks.
 *
 * The signature is verified with `hash_equals` so a wrong token reveals
 * nothing through timing. Payload parsing errors return FALSE rather than
 * throwing — verification must never blow up on attacker-controlled input.
 */
final class TokenManager
{
    /**
     * @param string $secret
     *   HMAC key. Must be non-empty when challenge plugins are active —
     *   `Firewall::create()` fails fast if a challenge plugin is configured
     *   without a secret.
     *
     * @throws ConfigurationException
     *   When the secret is empty.
     */
    public function __construct(private string $secret)
    {
        if ($this->secret === '') {
            throw new ConfigurationException(
                'Challenge token secret is empty. Set `challenge.secret` in '
                . 'firewall config (typically via env var) before enabling '
                . 'response: challenge plugins.'
            );
        }
    }

    /**
     * Mint a pass token bound to the request's client IP.
     *
     * @param Request $request
     *   The request that just solved the challenge.
     * @param int $ttl
     *   Token lifetime in seconds. Falls back to 3600 (1h) if non-positive.
     *
     * @return string
     *   The serialized token, ready to set as a cookie value.
     */
    public function mint(Request $request, int $ttl): string
    {
        $ttl = $ttl > 0 ? $ttl : 3600;

        $payload = [
            'ip' => (string) $request->getClientIp(),
            'exp' => time() + $ttl,
            'nonce' => bin2hex(random_bytes(16)),
        ];

        $payloadEncoded = self::base64UrlEncode((string) json_encode($payload));
        $signature = self::base64UrlEncode(hash_hmac('sha256', $payloadEncoded, $this->secret, true));

        return $payloadEncoded . '.' . $signature;
    }

    /**
     * Verify a token against the current request.
     *
     * @param string $token
     *   The candidate token (from cookie or header).
     * @param Request $request
     *   The request being evaluated.
     *
     * @return bool
     *   TRUE only if signature, IP binding, and expiry all pass.
     */
    public function verify(string $token, Request $request): bool
    {
        if ($token === '' || substr_count($token, '.') !== 1) {
            return false;
        }

        [$payloadEncoded, $signature] = explode('.', $token, 2);
        if ($payloadEncoded === '' || $signature === '') {
            return false;
        }

        $expectedSignature = self::base64UrlEncode(
            hash_hmac('sha256', $payloadEncoded, $this->secret, true)
        );

        if (!hash_equals($expectedSignature, $signature)) {
            return false;
        }

        $payloadJson = self::base64UrlDecode($payloadEncoded);
        if ($payloadJson === false) {
            return false;
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return false;
        }

        if (!isset($payload['ip'], $payload['exp']) || !is_int($payload['exp'])) {
            return false;
        }

        if ($payload['exp'] <= time()) {
            return false;
        }

        return $payload['ip'] === $request->getClientIp();
    }

    /**
     * Sign an arbitrary opaque string (used by providers to sign their
     * per-challenge nonces — e.g. the MathChallengeProvider signs the
     * expected answer + expiry so it stays stateless).
     */
    public function sign(string $data): string
    {
        return self::base64UrlEncode(hash_hmac('sha256', $data, $this->secret, true));
    }

    /**
     * Constant-time signature check for provider-signed payloads.
     */
    public function verifySignature(string $data, string $signature): bool
    {
        return hash_equals($this->sign($data), $signature);
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string|false
    {
        $padded = $data . str_repeat('=', (4 - strlen($data) % 4) % 4);
        return base64_decode(strtr($padded, '-_', '+/'), true);
    }
}
