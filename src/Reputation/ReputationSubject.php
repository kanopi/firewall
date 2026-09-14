<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Reputation;

/**
 * The thing a reputation service is being asked about (#341).
 *
 * Until 2.28.0 that was always the client address, which covered "is this
 * address known bad" and nothing else. The other half of what a reputation
 * service is for is the thing being **submitted**: an email at signup against a
 * disposable-mailbox or breach service, a phone number at checkout, a username
 * at login against a credential-stuffing corpus.
 *
 * All of those are the same lookup with a different subject, so the subject is
 * a value with a **kind** attached rather than a bare string. The kind is what
 * lets a provider refuse a question it cannot answer -- AbuseIPDB scores
 * addresses and nothing else -- and what keeps two subjects from sharing a
 * cache entry.
 *
 * ## The value is not for logging
 *
 * An email address is personal data and a username is credential-adjacent.
 * Neither belongs in a log line that a firewall writes on every request, so
 * `describe()` is what gets logged: the kind, and a short digest that is stable
 * enough to correlate two entries without being the value itself.
 */
final class ReputationSubject
{
    /**
     * The kind a rule gets when it names nothing.
     */
    public const CLIENT_IP = 'client_ip';

    /**
     * @param string $value
     *   What to look up. Already hashed when `$hashed` is true.
     * @param string $kind
     *   Where it came from, in the field vocabulary rules already use:
     *   `client_ip`, `post.email`, `header.x-api-key`.
     * @param bool $hashed
     *   Whether `$value` is a digest of the real value rather than the value.
     *   Recorded so a log line can say so, and so nothing downstream treats a
     *   digest as something it could parse.
     */
    public function __construct(
        public readonly string $value,
        public readonly string $kind = self::CLIENT_IP,
        public readonly bool $hashed = false
    ) {
    }

    /**
     * Whether this subject is the client's address.
     *
     * The question a provider that only scores addresses has to be able to ask,
     * and the one that decides whether `public_only` means anything.
     *
     * @return bool
     *   TRUE when the subject is the address the request arrived from.
     */
    public function isAddress(): bool
    {
        return $this->kind === self::CLIENT_IP;
    }

    /**
     * A filesystem-safe fragment naming the kind.
     *
     * Part of the cache path, so a score for `post.email` and one for an
     * address never share an entry -- they are different questions, and on some
     * services different scales.
     *
     * @return string
     *   Lowercase, with anything else collapsed to `-`.
     */
    public function slug(): string
    {
        return (string) preg_replace('/[^a-z0-9]+/', '-', strtolower($this->kind));
    }

    /**
     * The subject as it is safe to write down.
     *
     * Never the value. A firewall writes log lines on every request, and an
     * email address or a username in one of them is a disclosure that outlives
     * the request by however long the logs are kept.
     *
     * @return string
     *   The kind, with a short digest when the subject is not an address.
     */
    public function describe(): string
    {
        if ($this->isAddress()) {
            // An address is already in the log line under its own key, and is
            // the one subject the operator can act on directly.
            return $this->kind . ' ' . $this->value;
        }

        return sprintf('%s %s%s', $this->kind, substr(hash('xxh128', $this->value), 0, 12), $this->hashed ? ' (hashed)' : '');
    }
}
