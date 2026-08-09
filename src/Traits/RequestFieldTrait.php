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
 * Reads attacker-controlled request fields without ever throwing (#130).
 *
 * `InputBag::get()` raises `BadRequestException` when the posted value is an
 * array, so reading `altcha[]=x` through it turns one crafted POST field into
 * an uncaught exception and a 500. That matters most on the challenge flow:
 * `ChallengeProviderInterface::verifySolution()` is contractually forbidden
 * from throwing, and `Firewall::handleChallengeSubmission()` does not catch.
 *
 * The raw bag is inspected instead and anything that is not a string is
 * treated as absent — an array-valued `challenge_answer` is not a wrong
 * answer to be reported, it is simply not an answer.
 */
trait RequestFieldTrait
{
    /**
     * Read a POST body field as a string, or the empty string.
     *
     * @param Request $request
     *   The request carrying the submission.
     * @param string $field
     *   Body field name.
     * @param bool $trim
     *   Whether to trim surrounding whitespace from the value.
     *
     * @return string
     *   The posted value, or '' when it is absent or not a string.
     */
    protected function postedString(Request $request, string $field, bool $trim = true): string
    {
        $raw = $request->request->all()[$field] ?? '';

        if (!is_string($raw)) {
            return '';
        }

        return $trim ? trim($raw) : $raw;
    }
}
