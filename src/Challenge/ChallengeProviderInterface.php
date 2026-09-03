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
     * Form field naming the provider that rendered this interstitial.
     *
     * Once plugins can pick their own provider, the submission has to say
     * which one it answers. `handleChallengeSubmission()` fires on a POST
     * to `challenge.path` with the matched plugin long gone, so the only
     * thing left that can carry the answer is the form itself.
     *
     * The value is `name.signature`, signed with `challenge.secret` via
     * `TokenManager::sign()` — the same stateless carry the math provider
     * uses for its answer. `InterstitialRenderer` emits the field from the
     * `provider_token` render context, so any provider built on it gets
     * this for free; a provider rendering its own document should copy
     * `$context['provider_token']` into a hidden field of this name.
     * Omitting it is not fatal — the submission is then verified by
     * `challenge.provider`, and the pass token is scoped to that — but a
     * plugin-named provider will never see its own solutions.
     */
    public const PROVIDER_FIELD = 'challenge_provider';

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
     *     - provider_token: Signed `name.signature` identifying this
     *                      provider to the submission handler. Pass it
     *                      through to InterstitialRenderer, or render it
     *                      into a hidden PROVIDER_FIELD input.
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
