<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Challenge;

use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Turnstile provider with Cloudflare replaced by a standing "yes".
 *
 * Registered by FQCN in `challenge.provider` so the integration suite can
 * walk the whole submission flow — form fields, pass-token minting, cookie
 * delivery — without a network call. Everything except the siteverify round
 * trip is the real provider.
 */
class AlwaysVerifyingTurnstileProvider extends TurnstileChallengeProvider
{
    /**
     * {@inheritdoc}
     */
    protected function fetch(string $token, Request $request): array
    {
        return ['verified' => true, 'error_codes' => [], 'transport_error' => null];
    }
}
