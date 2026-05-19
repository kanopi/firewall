<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Exception;

/**
 * Thrown in FirewallMode::Exception when a challenge POST is successfully
 * verified.
 *
 * In production the Firewall would set the pass-token cookie and emit a
 * JSON/303 response — neither is observable from a test suite. This
 * exception carries the minted token so tests can assert that a follow-up
 * request bearing the token will pass evaluation.
 */
class ChallengeSolvedException extends FirewallException
{
    public function __construct(
        private readonly string $token,
        private readonly string $redirect,
        ?\Throwable $previous = null
    ) {
        parent::__construct('Challenge solved', 0, $previous);
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getRedirect(): string
    {
        return $this->redirect;
    }
}
