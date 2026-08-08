<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Challenge;

use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * reCAPTCHA provider with Google replaced by a standing "yes".
 *
 * Registered by FQCN in `challenge.provider` so the integration suite can
 * walk the whole submission flow — form fields, pass-token minting, cookie
 * delivery — without a network call. Everything except the siteverify round
 * trip is the real provider.
 *
 * The canned response carries a top score and the default action, so it
 * satisfies the v3 gates as well as v2's plain yes.
 */
class AlwaysVerifyingRecaptchaProvider extends RecaptchaChallengeProvider
{
    /**
     * {@inheritdoc}
     */
    protected function fetch(string $token, Request $request): array
    {
        return [
            'verified' => true,
            'error_codes' => [],
            'transport_error' => null,
            'score' => 1.0,
            'action' => self::DEFAULT_ACTION,
        ];
    }
}
