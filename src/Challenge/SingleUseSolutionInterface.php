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
 * Opt-in contract for providers whose solutions must not be replayed.
 *
 * A stateless provider verifies a solution purely from the posted payload,
 * which means the same payload verifies every time it is submitted until
 * it expires. For a proof-of-work challenge that is a real weakness: the
 * cost is paid once and the result can be redistributed, so an attacker
 * solves a single challenge and hands the payload to as many clients as
 * they like, each minting its own pass token.
 *
 * Providers that implement this interface hand `Firewall` an identifier
 * for the solution in the current request. `Firewall` — which owns the
 * storage backend — records it and refuses any later submission carrying
 * the same identifier.
 *
 * This is deliberately separate from `ChallengeProviderInterface` so that
 * existing custom providers keep working untouched, and because it is not
 * universally applicable: a provider whose solutions are not unique per
 * render cannot use it. `MathChallengeProvider` is exactly that case —
 * its signed state is `answer|expiry`, and with only nine possible answers
 * two visitors served in the same second routinely share one, so treating
 * that value as single-use would reject legitimate solvers.
 */
interface SingleUseSolutionInterface
{
    /**
     * Identify the solution carried by this request.
     *
     * Called only after `verifySolution()` has already returned TRUE, so
     * implementations may assume the payload is well-formed and authentic
     * and do not need to re-validate it.
     *
     * The identifier must be unique per issued challenge and derived from
     * signed material, otherwise an attacker could vary it to sidestep the
     * consumed-solution record.
     *
     * @param Request $request
     *   The POST request carrying the visitor's solution.
     *
     * @return array{id: string, expires: int}|null
     *   `id` uniquely identifies the solved challenge; `expires` is the
     *   unix timestamp after which the solution would be rejected anyway,
     *   used to bound how long the consumed-solution record is kept.
     *   NULL opts this particular request out of replay tracking.
     */
    public function getSolutionReceipt(Request $request): ?array;
}
