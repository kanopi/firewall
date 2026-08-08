<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Challenge;

use Symfony\Component\HttpFoundation\Request;

/**
 * Contract for challenge providers (math, Turnstile, reCAPTCHA, …).
 *
 * A provider owns two halves of the challenge round-trip:
 *   1. Rendering the interstitial body that asks the visitor to prove they
 *      are human.
 *   2. Verifying the answer the visitor posts back.
 *
 * Implementations MUST be self-contained: any nonce / signed state required
 * to verify the answer should be embedded in the interstitial output (typically
 * as a hidden form field) so the server stays stateless between the render
 * and verify steps.
 */
interface ChallengeProviderInterface
{
    /**
     * Form field carrying the post-success redirect target.
     *
     * Part of the contract rather than each provider's own constant:
     * `Firewall::handleChallengeSubmission()` reads the posted solution
     * without knowing which provider rendered it, so the field name has
     * to be fixed across every implementation.
     */
    public const REDIRECT_FIELD = 'redirect_to';

    /**
     * Form field carrying the per-plugin pass-token TTL in seconds.
     *
     * Fixed across implementations for the same reason as REDIRECT_FIELD.
     */
    public const TTL_FIELD = 'ttl';

    /**
     * Short identifier used in `challenge.provider` config (e.g. "math").
     */
    public function getName(): string;

    /**
     * Render the challenge interstitial HTML body.
     *
     * @param Request $request
     *   The blocked request that triggered the challenge.
     * @param array<string, string> $context
     *   Render-time data injected by the Firewall:
     *     - submit_url:    URL the form should POST to.
     *     - redirect_to:   URL to send the visitor to after success.
     *     - ttl:           Token TTL in seconds (per-plugin metadata).
     *     - cookie_name:   Cookie that will carry the pass token.
     *     - header_name:   Header for the localStorage delivery path.
     *
     * @return string
     *   Complete HTML document.
     */
    public function renderInterstitial(Request $request, array $context): string;

    /**
     * Verify a posted challenge solution.
     *
     * @param Request $request
     *   The POST request carrying the visitor's answer.
     *
     * @return bool
     *   TRUE if the solution is valid, FALSE otherwise.
     */
    public function verifySolution(Request $request): bool;
}
