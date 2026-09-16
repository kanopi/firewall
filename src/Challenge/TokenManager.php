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
 *   payload = JSON{ip, iat, exp, nonce, aud, prv}
 *   hmac    = HMAC-SHA256(payload, secret)
 *
 * Token binding (verified on every request):
 *   - `ip`    must equal `$request->getClientIp()` at verify time.
 *   - `exp`   is a unix timestamp; tokens past it are rejected.
 *   - `iat`   is when the pass was issued, and exists so a cutoff can be
 *             drawn across everything older than a moment without touching
 *             the secret. See `challenge.passes_valid_from` (#368).
 *   - `nonce` is 128 random bits to keep two same-second mints distinct in
 *             downstream logs and to prevent precomputed-token attacks.
 *   - `aud`   scopes the token to one challenge configuration. Without it,
 *             any two Firewall instances sharing a secret would accept
 *             each other's tokens, so a token earned on a weak challenge
 *             could be spent on a route protected by a stronger one — the
 *             weakest challenge would set the security of all of them.
 *   - `prv`   names the provider that was actually solved. `aud` scopes a
 *             token across *instances*; `prv` scopes it across *rules
 *             within* one, which is what per-plugin providers need. With
 *             one TokenManager serving a math rule and a reCAPTCHA rule,
 *             `aud` is identical for both, so without `prv` the math token
 *             would satisfy the reCAPTCHA rule and reintroduce the exact
 *             hole `aud` closes between instances.
 *
 * Two levers withdraw a pass before its `exp`, and both are off by default
 * because the stateless property is the point of the design (#368):
 * `challenge.passes_valid_from` draws a line in time and costs nothing, and
 * `challenge.revocable` enables a per-nonce list at the price of one storage
 * read on an otherwise-valid token.
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
     * @param string $audience
     *   Scope this manager mints and accepts tokens for. `Firewall`
     *   defaults it to the configured provider name, so a `math` token is
     *   not accepted by an `altcha`-protected instance. Operators running
     *   several instances with the same provider and the same secret can
     *   set `challenge.audience` explicitly to keep them separate.
     * @param string $defaultProvider
     *   The `challenge.provider` name, used only to decide what a token
     *   carrying no `prv` claim is worth. Such tokens predate per-plugin
     *   providers, so the only provider that could have minted one is the
     *   global default — they are accepted for that provider and rejected
     *   for any other. That keeps an upgrade from re-challenging everyone
     *   holding a live token, without letting a legacy token stand in for
     *   a provider it was never earned against.
     * @param int $passesValidFrom
     *   Reject every pass issued before this unix timestamp. Zero is off,
     *   which is the default and costs nothing.
     * @param PassRevocationList|null $passRevocationList
     *   Per-token revocation, or NULL for none. NULL means no storage is
     *   consulted on any verification — a deployment that never revokes
     *   anything should not pay for the ability.
     *
     * @throws ConfigurationException
     *   When the secret is empty.
     */
    public function __construct(
        private readonly string $secret,
        private readonly string $audience = '',
        private readonly string $defaultProvider = '',
        private readonly int $passesValidFrom = 0,
        private readonly ?PassRevocationList $passRevocationList = null
    ) {
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
     * @param string $provider
     *   Name of the provider whose challenge was solved. Recorded as the
     *   `prv` claim so the token only satisfies rules served by that
     *   provider. Empty omits the claim, which is what a caller minting
     *   outside the per-provider flow wants.
     *
     * @return string
     *   The serialized token, ready to set as a cookie value.
     */
    public function mint(Request $request, int $ttl, string $provider = ''): string
    {
        $ttl = $ttl > 0 ? $ttl : 3600;

        $now = time();
        $payload = [
            'ip' => (string) $request->getClientIp(),
            'iat' => $now,
            'exp' => $now + $ttl,
            'nonce' => bin2hex(random_bytes(16)),
            'aud' => $this->audience,
        ];

        if ($provider !== '') {
            $payload['prv'] = $provider;
        }

        $payloadEncoded = $this->base64UrlEncode((string) json_encode($payload));
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $payloadEncoded, $this->secret, true));

        return $payloadEncoded . '.' . $signature;
    }

    /**
     * Verify a token against the current request.
     *
     * @param string $token
     *   The candidate token (from cookie or header).
     * @param Request $request
     *   The request being evaluated.
     * @param string|null $provider
     *   Provider the token has to have been earned against — the one
     *   serving the rule being evaluated. NULL skips the check, which is
     *   only right when a single provider serves every challenge rule.
     *
     * @return bool
     *   TRUE only if signature, IP binding, expiry, audience and (when
     *   asked for) provider scope all pass.
     */
    public function verify(string $token, Request $request, ?string $provider = null): bool
    {
        if ($token === '' || substr_count($token, '.') !== 1) {
            return false;
        }

        [$payloadEncoded, $signature] = explode('.', $token, 2);
        if ($payloadEncoded === '' || $signature === '') {
            return false;
        }

        $expectedSignature = $this->base64UrlEncode(hash_hmac('sha256', $payloadEncoded, $this->secret, true));

        if (!hash_equals($expectedSignature, $signature)) {
            return false;
        }

        $payloadJson = $this->base64UrlDecode($payloadEncoded);
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

        if ($this->passesValidFrom > 0 && $this->issuedAt($payload) < $this->passesValidFrom) {
            return false;
        }

        // Fail closed on a missing `aud`: tokens minted before this claim
        // existed are rejected, costing their holders one extra challenge
        // rather than leaving the cross-instance hole open.
        if (!isset($payload['aud']) || !is_string($payload['aud']) || $payload['aud'] !== $this->audience) {
            return false;
        }

        if ($provider !== null && !$this->scopeMatches($payload['prv'] ?? null, $provider)) {
            return false;
        }

        if ($payload['ip'] !== $request->getClientIp()) {
            return false;
        }

        // Last, and only on a token that is otherwise entirely good. Every
        // check above is arithmetic on bytes already in hand; this one is a
        // round trip to the store, so it is not paid for a token that was
        // going to be refused anyway -- and not paid at all unless
        // `challenge.revocable` is on.
        return !$this->passRevocationList instanceof PassRevocationList
            || !$this->passRevocationList->isRevoked(is_string($payload['nonce'] ?? null) ? $payload['nonce'] : '');
    }

    /**
     * Read a token's claims, without checking them.
     *
     * The signature *is* checked -- an unsigned payload is somebody's guess
     * about a token rather than a token -- but expiry, audience, provider, IP
     * binding and revocation are not. This is what an operator holding a pass
     * needs in order to act on it: the `nonce` to revoke and the `exp` to
     * revoke it until.
     *
     * @param string $token
     *   The candidate token.
     *
     * @return array<string, mixed>|null
     *   The decoded claims, or NULL when the token is not one this manager
     *   signed.
     */
    public function inspect(string $token): ?array
    {
        if ($token === '' || substr_count($token, '.') !== 1) {
            return null;
        }

        [$payloadEncoded, $signature] = explode('.', $token, 2);

        if ($payloadEncoded === '' || $signature === '') {
            return null;
        }

        if (!hash_equals($this->base64UrlEncode(hash_hmac('sha256', $payloadEncoded, $this->secret, true)), $signature)) {
            return null;
        }

        $payloadJson = $this->base64UrlDecode($payloadEncoded);

        if ($payloadJson === false) {
            return null;
        }

        $payload = json_decode($payloadJson, true);

        return is_array($payload) ? $payload : null;
    }

    /**
     * When a pass was issued, for comparison against a cutoff.
     *
     * A token carrying no `iat` predates the claim, and cannot be dated. It is
     * treated as issued at the beginning of time, so **any** cutoff withdraws
     * it -- which is the right way round: `passes_valid_from` is a revocation
     * lever, and the passes an operator most wants to withdraw with it are the
     * ones minted before the firewall was fixed. It is off by default, so no
     * upgrade re-challenges anybody who does not reach for it.
     *
     * @param array<array-key, mixed> $payload
     *   The decoded claims.
     *
     * @return int
     *   The issue time, or 0 when the token does not carry one.
     */
    private function issuedAt(array $payload): int
    {
        return is_int($payload['iat'] ?? null) ? $payload['iat'] : 0;
    }

    /**
     * Is a token's `prv` claim good for the provider being asked about?
     *
     * Strict by design: a token attests to the one challenge its holder
     * actually solved, so a client that trips a math rule and a reCAPTCHA
     * rule solves both. Ranking providers by strength so a "harder" token
     * covered an "easier" rule would mean the firewall imposing an ordering
     * on services it does not control — and custom providers have no place
     * on such a ladder at all.
     *
     * @param mixed $claim
     *   The `prv` value from the payload, or NULL when absent.
     * @param string $provider
     *   Provider the rule being evaluated is served by.
     */
    private function scopeMatches(mixed $claim, string $provider): bool
    {
        // A token minted before `prv` existed can only have come from the
        // globally configured provider, so it is worth exactly that and
        // nothing more.
        if ($claim === null) {
            return $provider === $this->defaultProvider;
        }

        return is_string($claim) && hash_equals($claim, $provider);
    }

    /**
     * Sign an arbitrary opaque string (used by providers to sign their
     * per-challenge nonces — e.g. the MathChallengeProvider signs the
     * expected answer + expiry so it stays stateless).
     */
    public function sign(string $data): string
    {
        return $this->base64UrlEncode(hash_hmac('sha256', $data, $this->secret, true));
    }

    /**
     * Constant-time signature check for provider-signed payloads.
     */
    public function verifySignature(string $data, string $signature): bool
    {
        return hash_equals($this->sign($data), $signature);
    }

    /**
     * Base64url-encode a string (RFC 4648 §5, padding stripped).
     *
     * Tokens travel in cookies and HTTP headers, so `+`, `/` and `=` are
     * translated away to keep the value safe to transport without further
     * escaping.
     *
     * @param string $data
     *   Raw bytes to encode.
     *
     * @return string
     *   The base64url representation, without `=` padding.
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode a base64url string produced by self::base64UrlEncode().
     *
     * Re-adds the stripped padding before decoding and uses strict mode so
     * attacker-supplied garbage is rejected rather than silently truncated.
     *
     * @param string $data
     *   The base64url payload (padding optional).
     *
     * @return string|false
     *   The decoded bytes, or FALSE when the input is not valid base64url.
     */
    private function base64UrlDecode(string $data): string|false
    {
        $padded = $data . str_repeat('=', (4 - strlen($data) % 4) % 4);
        return base64_decode(strtr($padded, '-_', '+/'), true);
    }
}
