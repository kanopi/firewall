<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Traits;

use Symfony\Component\HttpFoundation\Request;

/**
 * Whether a header the edge added may be believed for this request.
 *
 * An edge header is a **claim**. `CF-IPCountry: US` and `cf-bot-score: 99` are
 * worth exactly what the path they arrived by is worth, and a request straight
 * to the origin can carry either. Against a `response: allow` rule that is not
 * a weakened control but a complete bypass, because an allow match
 * short-circuits everything after it.
 *
 * Symfony already knows whether a request arrived through a trusted proxy, and
 * a deployment behind a CDN has to configure that anyway for `getClientIp()` to
 * be right. So that is the gate, rather than a second list to maintain.
 *
 * Shared because two plugins now read edge headers -- geolocation since #176
 * and bot signals since #206 -- and a trust boundary implemented twice is a
 * trust boundary that will eventually be implemented differently.
 */
trait EdgeTrustTrait
{
    /**
     * Whether an edge header may be believed for this request.
     *
     * @param Request $request
     *   The request under evaluation.
     *
     * @return bool
     *   TRUE when the headers may be read.
     */
    protected function edgeIsTrusted(Request $request): bool
    {
        return $request->isFromTrustedProxy();
    }

    /**
     * Say that edge headers are being ignored, and what to do about it.
     *
     * Loud rather than quiet. Without trusted proxies configured the rule
     * matches nothing, which looks exactly like "no bots are visiting" or
     * "nobody from those countries is visiting" -- the failure #165 is about,
     * in a place where it means the control is simply off.
     *
     * @param Request $request
     *   The request under evaluation.
     * @param string $rule
     *   What the rule is called, for the message.
     * @param array<string, mixed> $context
     *   Anything else worth recording.
     */
    protected function warnEdgeIsUntrusted(Request $request, string $rule, array $context = []): void
    {
        $this->getLogger()->warning(
            $rule . ' is reading edge headers but this request did not arrive via a trusted proxy, so '
            . 'the headers are being ignored. Call Request::setTrustedProxies() with your CDN ranges, '
            . 'or these rules will never match.',
            $this->getContext($request, $context + ['trusted_proxies' => Request::getTrustedProxies()])
        );
    }
}
