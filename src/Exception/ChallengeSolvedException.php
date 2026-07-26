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
    /**
     * Constructs a new ChallengeSolvedException object.
     *
     * @param string $token
     *   The freshly minted pass token. In `block` mode this would have been
     *   written to the pass-token cookie instead.
     * @param string $redirect
     *   Sanitized URL the visitor should be sent to now that the challenge
     *   is solved.
     * @param \Throwable|null $previous
     *   Previous exception for chaining, if any.
     */
    public function __construct(
        private readonly string $token,
        private readonly string $redirect,
        ?\Throwable $previous = null
    ) {
        parent::__construct('Challenge solved', 0, $previous);
    }

    /**
     * The minted pass token.
     *
     * @return string
     *   Token value to hand back to the client — as the pass-token cookie,
     *   or as a body value the caller attaches to later requests via the
     *   configured challenge header.
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Where to send the visitor after a successful challenge.
     *
     * @return string
     *   A root-relative path, already sanitized — protocol-relative (`//`)
     *   and non-`/`-prefixed targets collapse to `/`, so this cannot send a
     *   visitor off-site. Safe to use directly in a `Location` header.
     */
    public function getRedirect(): string
    {
        return $this->redirect;
    }
}
