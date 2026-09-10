<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Event;

use Symfony\Component\HttpFoundation\Request;

/**
 * A challenge submission was refused (#218).
 *
 * `getReason()` is the value the firewall already logs, and it is worth reading rather than
 * counting failures in aggregate, because the three mean different things:
 *
 * - `invalid_solution` -- an ordinary wrong answer, or a bot.
 * - `solution_already_used` -- a correct answer being replayed, which is somebody
 *   redistributing work rather than doing it.
 * - `unknown_provider` -- the signed provider claim names a provider this firewall does not
 *   have. Either tampering, or a config that changed underneath an already-rendered page,
 *   and a sudden run of them after a deploy means the second.
 */
final class ChallengeFailed extends DecisionEvent
{
    /**
     * @param Request $request
     *   The submission request.
     * @param string $provider
     *   The provider that was asked to verify, as far as it could be resolved.
     * @param string $reason
     *   Why it was refused: `invalid_solution`, `solution_already_used` or
     *   `unknown_provider`.
     */
    public function __construct(
        Request $request,
        private readonly string $provider,
        private readonly string $reason
    ) {
        parent::__construct($request);
    }

    /**
     * The provider that refused it.
     *
     * @return string
     *   The provider name.
     */
    public function getProvider(): string
    {
        return $this->provider;
    }

    /**
     * Why it was refused.
     *
     * @return string
     *   One of `invalid_solution`, `solution_already_used`,
     *   `unknown_provider`.
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
