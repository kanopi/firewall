<?php

declare(strict_types=1);

namespace Kanopi\Firewall\Tests\Challenge;

use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Symfony\Component\HttpFoundation\Request;

/**
 * Turnstile provider with siteverify permanently unreachable.
 *
 * Stands in for a Cloudflare outage, egress filtering, or a DNS failure, so
 * the integration suite can assert what the `on_error` option actually does
 * to a live challenge flow.
 */
class UnreachableTurnstileProvider extends TurnstileChallengeProvider
{
    /**
     * {@inheritdoc}
     */
    protected function fetch(string $token, Request $request): array
    {
        return [
            'verified' => false,
            'error_codes' => [],
            'transport_error' => 'could not reach the Turnstile siteverify API',
        ];
    }
}
