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
 * A client answered a challenge correctly and has been issued a pass token (#218).
 *
 * The other half of `RequestChallenged`, and the pair is the whole reason this event
 * exists: a challenge nobody solves is a challenge that is too hard, and until now the only
 * way to notice was to count two log messages.
 *
 * Dispatched after the token is minted, so a listener can trust that the client really is
 * about to be let through.
 */
final class ChallengeSolved extends DecisionEvent
{
    /**
     * @param Request $request
     *   The submission request.
     * @param string $provider
     *   The provider name the solution was scoped to.
     * @param int $ttl
     *   How long, in seconds, the issued pass token is good for.
     */
    public function __construct(
        Request $request,
        private readonly string $provider,
        private readonly int $ttl
    ) {
        parent::__construct($request);
    }

    /**
     * The provider whose challenge was solved.
     *
     * @return string
     *   The configured provider name.
     */
    public function getProvider(): string
    {
        return $this->provider;
    }

    /**
     * How long the pass token lasts.
     *
     * @return int
     *   Lifetime in seconds.
     */
    public function getTtl(): int
    {
        return $this->ttl;
    }
}
