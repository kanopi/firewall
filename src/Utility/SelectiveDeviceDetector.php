<?php

declare(strict_types=1);

/*
 * This file is part of the Firewall package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Utility;

use DeviceDetector\DeviceDetector;

/**
 * A DeviceDetector that stops once it has parsed as much as was asked for (#108).
 *
 * `DeviceDetector::parse()` always runs every phase. Most firewall rules need
 * far less: a config asking only `bot:true` has no use for brand and model
 * detection, yet pays for it on every request.
 *
 * WHY PHASES ARE CUMULATIVE RATHER THAN INDIVIDUALLY SELECTABLE:
 *
 * They are not independent. `parseDevice()` reads the OS and client results to
 * infer a device type — `Android` plus a browser becomes `smartphone`, and
 * there are several more rules like it. Running device detection without
 * having run OS and client first would produce a *different, wrong* device
 * type rather than simply a slower one. So this class exposes a depth, not a
 * set: name the deepest phase you need and everything before it runs too, in
 * the order `parse()` itself uses.
 *
 * WHY BOT DETECTION ALWAYS RUNS:
 *
 * `parse()` returns early once a bot is identified, so a bot user agent never
 * reaches client or device parsing. Skipping bot detection to save time would
 * let it through to those phases, and `getClient()` would start returning
 * values for Googlebot where today it returns nothing — a silent change in
 * what a blocking rule matches, which is exactly what this optimisation must
 * not cause.
 *
 * @see \Kanopi\Firewall\Plugins\UserAgent
 */
class SelectiveDeviceDetector extends DeviceDetector
{
    /**
     * Parse phases, in the order `DeviceDetector::parse()` runs them.
     */
    public const PHASE_BOT = 'bot';

    public const PHASE_OS = 'os';

    public const PHASE_CLIENT = 'client';

    public const PHASE_DEVICE = 'device';

    /**
     * Depth order. Index position is the comparison; the values are the labels.
     *
     * @var array<int, string>
     */
    public const PHASES = [
        self::PHASE_BOT,
        self::PHASE_OS,
        self::PHASE_CLIENT,
        self::PHASE_DEVICE,
    ];

    /**
     * Whether parseUpTo() has run.
     *
     * `DeviceDetector::$parsed` is private, so the parent's re-entrancy flag
     * cannot be set from here. Tracking it separately and overriding
     * `isParsed()` preserves the contract exactly: a later `parse()` still
     * sees the object as parsed and returns early, rather than silently
     * redoing the work this class just avoided.
     */
    private bool $selectivelyParsed = false;

    /**
     * {@inheritdoc}
     */
    public function isParsed(): bool
    {
        return $this->selectivelyParsed || parent::isParsed();
    }

    /**
     * Parse no further than the named phase.
     *
     * Deliberately mirrors `DeviceDetector::parse()` line for line — the
     * `isParsed()` guard, the `parsed` flag, the empty / letterless user agent
     * short circuit, and the bot early return. Any divergence here is a
     * behaviour change in disguise, so the structure is kept recognisably the
     * same rather than tidied up.
     *
     * @param string $upTo
     *   The deepest phase to run. An unrecognised value runs everything, which
     *   is the safe direction to fail: the cost is a lost optimisation, never
     *   a rule that quietly stops matching.
     */
    public function parseUpTo(string $upTo = self::PHASE_DEVICE): void
    {
        if ($this->isParsed()) {
            return;
        }

        $this->selectivelyParsed = true;

        // Mirrors parse(): nothing to detect in an empty or letterless agent
        // when no client hints were supplied.
        $hasParseableAgent = !empty($this->userAgent)
            && \preg_match('/([a-z])/i', $this->userAgent) === 1;

        if (empty($this->clientHints) && !$hasParseableAgent) {
            return;
        }

        $depth = $this->depthOf($upTo);

        // Always. See the class docblock.
        $this->parseBot();

        if ($this->isBot()) {
            return;
        }

        if ($depth < $this->depthOf(self::PHASE_OS)) {
            return;
        }

        $this->parseOs();

        if ($depth < $this->depthOf(self::PHASE_CLIENT)) {
            return;
        }

        $this->parseClient();

        if ($depth < $this->depthOf(self::PHASE_DEVICE)) {
            return;
        }

        $this->parseDevice();
    }

    /**
     * Position of a phase in the parse order.
     *
     * @param string $phase
     *   A phase name.
     *
     * @return int
     *   Its index, or the deepest index when the name is not recognised.
     */
    protected function depthOf(string $phase): int
    {
        $index = array_search($phase, self::PHASES, true);

        return $index === false ? count(self::PHASES) - 1 : $index;
    }
}
