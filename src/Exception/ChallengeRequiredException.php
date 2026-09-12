<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * A rule demanded a challenge, and `mode: exception` is leaving the response to the host.
 *
 * ## Why this carries so much
 *
 * In `mode: exception` the host renders the interstitial, so the host needs everything
 * `sendChallengeResponse()` would have used. Before 2.26.0 it got a message and nothing
 * else, and there was no public route to the rest: the registry and the token manager are
 * not exposed, `signProviderName()` is `protected`, and `Firewall` is `final` with a
 * `protected` constructor, so it cannot be subclassed either (#311).
 *
 * A host could assemble five of the six context values by hand. It could not produce
 * `provider_token`, which is the signed claim naming the provider that was actually put in
 * front of the visitor. **Omitting it does not degrade.** The submission is then verified by
 * the default provider, the minted pass token carries that provider's `prv` claim, the rule
 * that demanded the challenge refuses that token, and the visitor is served the same
 * interstitial forever — with nothing on the path logged above `notice`.
 *
 * So the exception carries the rendered answer rather than the parts:
 *
 * ```php
 * try {
 *     $firewall->evaluate($request);
 * } catch (ChallengeRequiredException $e) {
 *     return new Response($e->renderInterstitial($request), 200, [
 *         'Content-Type'  => 'text/html; charset=utf-8',
 *         'Cache-Control' => 'no-store',
 *     ]);
 * }
 * ```
 *
 * `getProvider()` and `getRenderContext()` remain available for a host that wants to render
 * differently, but nothing is required to reassemble that context to get a correct result.
 *
 * `ChallengeSolvedException` has carried its token and redirect since the challenge flow
 * shipped; this is the same idea applied to the other half of it.
 */
class ChallengeRequiredException extends FirewallException
{
    /**
     * Constructs a new ChallengeRequiredException object.
     *
     * @param string $message
     *   Human-readable reason, naming the plugin that demanded the challenge.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     * @param ChallengeProviderInterface|null $challengeProvider
     *   The provider that will serve the interstitial. NULL only where the
     *   firewall itself could not resolve one, which is a misconfiguration it
     *   reports separately.
     * @param string $providerName
     *   The configured name of that provider — `math`, `recaptcha`, a class.
     *   This is what the pass token ends up scoped to.
     * @param array<string, string> $renderContext
     *   Exactly what `ChallengeProviderInterface::renderInterstitial()` expects,
     *   `provider_token` included.
     */
    public function __construct(
        string $message,
        ?\Throwable $previous = null,
        private readonly ?ChallengeProviderInterface $challengeProvider = null,
        private readonly string $providerName = '',
        private readonly array $renderContext = []
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * The provider serving this challenge.
     *
     * @return ChallengeProviderInterface|null
     *   The provider, or NULL when one could not be resolved.
     */
    public function getProvider(): ?ChallengeProviderInterface
    {
        return $this->challengeProvider;
    }

    /**
     * The configured name of that provider.
     *
     * Worth having separately from `getProvider()->getName()`: a rule can name its own
     * provider, and it is this name the pass token is scoped to.
     *
     * @return string
     *   The provider name, or an empty string when none was resolved.
     */
    public function getProviderName(): string
    {
        return $this->providerName;
    }

    /**
     * Everything the interstitial needs, assembled by the firewall.
     *
     * @return array<string, string>
     *   `submit_url`, `redirect_to`, `ttl`, `cookie_name`, `header_name` and
     *   `provider_token`. Empty only when constructed without one.
     */
    public function getRenderContext(): array
    {
        return $this->renderContext;
    }

    /**
     * Render the interstitial this challenge calls for.
     *
     * The one-line path, and the reason this class carries a provider at all: a host that
     * calls this cannot omit `provider_token`, cannot pass a context meant for a different
     * provider, and cannot lock a visitor out by assembling five of six values correctly.
     *
     * @param Request $request
     *   The request being challenged.
     *
     * @return string
     *   The interstitial's HTML.
     *
     * @throws ConfigurationException
     *   When no provider was resolved, which means the firewall could not have
     *   rendered it either.
     */
    public function renderInterstitial(Request $request): string
    {
        if (!$this->challengeProvider instanceof ChallengeProviderInterface) {
            throw new ConfigurationException(
                'No challenge provider was resolved for this challenge, so there is nothing to render. '
                . 'This exception was raised without one; check the firewall log for the configuration error.'
            );
        }

        return $this->challengeProvider->renderInterstitial($request, $this->renderContext);
    }
}
