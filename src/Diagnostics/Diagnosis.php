<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Diagnostics;

/**
 * One thing the doctor looked at, and what it found.
 *
 * Three statuses, and the difference between the last two is what an operator should do
 * about it rather than how alarming it sounds:
 *
 * - `ok` -- checked, and nothing to do.
 * - `warning` -- the firewall is enforcing, but something is degraded or unverifiable.
 *   A stale GeoIP database still answers; it just answers with last quarter's allocations.
 * - `error` -- a rule that was configured is not running, or the firewall would refuse to
 *   start. Something an operator asked for is not happening.
 *
 * `bin/firewall-doctor` exits non-zero on `error` only, so it can gate a deploy without a
 * stale database blocking one.
 */
final class Diagnosis
{
    public const OK = 'ok';

    public const WARNING = 'warning';

    public const ERROR = 'error';

    /**
     * @param string $status
     *   One of the constants above.
     * @param string $title
     *   The finding in one line, in the operator's terms.
     * @param string|null $detail
     *   What to do about it, or what was actually observed.
     * @param string|null $reference
     *   Where to read more -- a documentation path, not a full URL, so it stays
     *   right when the docs move host.
     */
    private function __construct(
        public readonly string $status,
        public readonly string $title,
        public readonly ?string $detail = null,
        public readonly ?string $reference = null
    ) {
    }

    /**
     * Checked, and nothing to do.
     *
     * @param string $title
     *   What was checked.
     * @param string|null $detail
     *   What was found, when the number is worth seeing.
     *
     * @return self
     *   The diagnosis.
     */
    public static function ok(string $title, ?string $detail = null): self
    {
        return new self(self::OK, $title, $detail);
    }

    /**
     * Enforcing, but degraded or unverifiable.
     *
     * @param string $title
     *   What was found.
     * @param string|null $detail
     *   What to do about it.
     * @param string|null $reference
     *   Documentation path.
     *
     * @return self
     *   The diagnosis.
     */
    public static function warning(string $title, ?string $detail = null, ?string $reference = null): self
    {
        return new self(self::WARNING, $title, $detail, $reference);
    }

    /**
     * Something configured is not happening.
     *
     * @param string $title
     *   What was found.
     * @param string|null $detail
     *   What to do about it.
     * @param string|null $reference
     *   Documentation path.
     *
     * @return self
     *   The diagnosis.
     */
    public static function error(string $title, ?string $detail = null, ?string $reference = null): self
    {
        return new self(self::ERROR, $title, $detail, $reference);
    }

    /**
     * The diagnosis as data, for `--json`.
     *
     * @return array<string, string|null>
     *   Status, title, detail and reference.
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'title' => $this->title,
            'detail' => $this->detail,
            'reference' => $this->reference,
        ];
    }
}
