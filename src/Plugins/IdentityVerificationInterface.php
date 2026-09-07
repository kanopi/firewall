<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Plugins;

use Symfony\Component\HttpFoundation\Request;

/**
 * A plugin whose match can be made conditional on proving who the client is.
 *
 * A rule that matches on something the client sends -- a user agent above all -- is
 * matching on an assertion, not a fact. That is fine for a block rule, where the cost of
 * being lied to is that an attacker declines to be blocked. It is not fine for an allow
 * rule, where the lie buys a bypass of everything below it (#199).
 *
 * Separate from `PluginInterface` for the same reason as `ObserveModeInterface`: adding a
 * method there would make every custom plugin fatally incomplete on a `composer update`.
 */
interface IdentityVerificationInterface
{
    /**
     * Whether a match should be allowed to stand.
     *
     * Called only after the plugin has already matched, so it costs nothing on the
     * overwhelming majority of requests.
     *
     * @param Request $request
     *   The request that matched.
     *
     * @return bool
     *   True when no verification is configured, or when it passed. False turns the match
     *   back into no match.
     */
    public function passesIdentityVerification(Request $request): bool;
}
