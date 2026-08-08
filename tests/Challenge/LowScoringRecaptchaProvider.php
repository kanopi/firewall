<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Challenge;

use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * reCAPTCHA provider whose tokens Google accepts but scores badly.
 *
 * The case that distinguishes v3 from every other built-in: siteverify is
 * reachable, the token is genuine and unspent, and the visitor is still
 * refused — by this provider's own threshold rather than by Google. The
 * integration suite uses it to prove that decision reaches the firewall as
 * a failed challenge rather than a minted pass token.
 */
class LowScoringRecaptchaProvider extends RecaptchaChallengeProvider
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
            'score' => 0.1,
            'action' => self::DEFAULT_ACTION,
        ];
    }
}
